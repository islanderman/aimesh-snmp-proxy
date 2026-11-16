import copy

import pytest

from aimesh_snmp_proxy.config import load_config
from aimesh_snmp_proxy.ops.onboard import Node, plan_nodes
from aimesh_snmp_proxy.ports import PortMap

ROOT = 16101
MAC_A = "02:00:00:00:00:0a"  # default name aimesh-00000a
MAC_B = "02:00:00:00:00:0b"
MAC_C = "02:00:00:00:00:0c"


@pytest.fixture
def setup(make_config, base_config):
    """Build a Config and a PortMap from overrides and ``(mac, ip[, pin])`` nodes."""

    def _setup(overrides=(), nodes=(), host=None, hostname=None):
        doc = copy.deepcopy(base_config)
        if host is not None:
            doc["asus"]["host"] = host
        if hostname is not None:
            doc["onboard"] = {"hostname": hostname}
        if overrides:
            doc["override"] = [dict(o) for o in overrides]
        cfg = load_config(make_config(doc), env={})
        pm = PortMap.load(cfg.ports_file, cfg.snmp.port_base, cfg.nodes.expected)
        for mac, ip, *pin in nodes:
            pm.assign(mac, ip=ip, pin=pin[0] if pin else None)
        return cfg, PortMap.load(
            cfg.ports_file, cfg.snmp.port_base, cfg.nodes.expected, read_only=True
        )

    return _setup


def by_port(nodes):
    return {node.port: node for node in nodes}


def test_pinned_nodes_get_default_names_in_port_order(setup):
    cfg, pm = setup(nodes=[(MAC_B, "192.168.50.50"), (MAC_A, "192.168.50.101")])
    nodes, warnings = plan_nodes(cfg, pm)
    assert [(n.port, n.role, n.hostname) for n in nodes] == [
        (ROOT, "root", "aimesh-root"),
        (16102, "node", "aimesh-00000a"),
        (16112, "node", "aimesh-00000b"),
    ]
    assert [n.skip for n in nodes] == [None, None, None]
    assert warnings == []


def test_the_root_is_aimesh_root_without_an_override(setup):
    cfg, pm = setup()
    (root,) = plan_nodes(cfg, pm)[0]
    assert root == Node(ROOT, "root", "aimesh-root")


def test_the_root_takes_the_override_that_matches_the_router_ip(setup):
    cfg, pm = setup(overrides=[{"match": "192.168.50.1", "sys_name": "aimesh-main"}])
    (root,) = plan_nodes(cfg, pm)[0]
    assert root == Node(ROOT, "root", "aimesh-main")


def test_the_root_can_be_excluded(setup):
    cfg, pm = setup(overrides=[{"match": "192.168.50.1", "exclude": True}])
    (root,) = plan_nodes(cfg, pm)[0]
    assert root.hostname is None
    assert root.skip == "excluded by override"


def test_the_root_is_aimesh_root_when_the_router_host_is_a_name(setup):
    cfg, pm = setup(host="router.asus.com")
    (root,) = plan_nodes(cfg, pm)[0]
    assert root == Node(ROOT, "root", "aimesh-root")


def test_a_mac_override_names_its_node(setup):
    cfg, pm = setup(
        overrides=[{"match": MAC_B.upper(), "sys_name": "aimesh-den"}],
        nodes=[(MAC_B, "192.168.50.50")],
    )
    assert by_port(plan_nodes(cfg, pm)[0])[16112].hostname == "aimesh-den"


def test_an_ip_override_in_the_expected_range_names_the_node_reserved_for_it(setup):
    cfg, pm = setup(
        overrides=[{"match": "192.168.50.102", "sys_name": "aimesh-hall"}],
        nodes=[(MAC_A, "192.168.50.101"), (MAC_B, "192.168.50.102")],
    )
    nodes = by_port(plan_nodes(cfg, pm)[0])
    assert nodes[16102].hostname == "aimesh-00000a"
    assert nodes[16103].hostname == "aimesh-hall"


def test_an_ip_override_with_a_port_names_the_node_pinned_there(setup):
    cfg, pm = setup(
        overrides=[
            {"match": "192.168.50.103", "sys_name": "aimesh-loft", "port": 16150}
        ],
        nodes=[(MAC_C, "192.168.50.103", 16150)],
    )
    nodes, warnings = plan_nodes(cfg, pm)
    assert by_port(nodes)[16150].hostname == "aimesh-loft"
    assert warnings == []


def test_an_ip_override_with_a_port_does_not_name_its_reserved_index(setup):
    cfg, pm = setup(
        overrides=[
            {"match": "192.168.50.101", "sys_name": "aimesh-moved", "port": 16150}
        ],
        nodes=[(MAC_A, "192.168.50.101", 16150), (MAC_B, "192.168.50.50", 16102)],
    )
    nodes = by_port(plan_nodes(cfg, pm)[0])
    assert nodes[16150].hostname == "aimesh-moved"
    assert nodes[16102].hostname == "aimesh-00000b"


def test_excluded_nodes_are_listed_but_skipped(setup):
    cfg, pm = setup(
        overrides=[{"match": MAC_A, "exclude": True}],
        nodes=[(MAC_A, "192.168.50.101")],
    )
    node = by_port(plan_nodes(cfg, pm)[0])[16102]
    assert (node.hostname, node.skip) == (None, "excluded by override")


def test_an_ip_override_onboard_cannot_place_skips_nodes_it_may_name(setup):
    cfg, pm = setup(
        overrides=[{"match": "192.168.50.200", "sys_name": "aimesh-shed"}],
        nodes=[(MAC_A, "192.168.50.101"), (MAC_B, "192.168.50.200")],
    )
    nodes, warnings = plan_nodes(cfg, pm)
    nodes = by_port(nodes)
    assert nodes[16102].skip is None
    assert nodes[16112].hostname == "aimesh-00000b"
    assert "match it by MAC" in nodes[16112].skip
    assert len(warnings) == 1
    assert "192.168.50.200" in warnings[0]


def test_all_digit_hostnames_are_refused(setup):
    cfg, pm = setup(
        overrides=[{"match": MAC_A, "sys_name": "4711"}],
        nodes=[(MAC_A, "192.168.50.101")],
    )
    node = by_port(plan_nodes(cfg, pm)[0])[16102]
    assert node.hostname == "4711"
    assert "device id" in node.skip


def test_a_clash_between_the_root_name_and_a_node_name_skips_both(setup):
    cfg, pm = setup(
        overrides=[{"match": "192.168.50.1", "sys_name": "AIMESH-00000A"}],
        nodes=[(MAC_A, "192.168.50.101")],
    )
    nodes = by_port(plan_nodes(cfg, pm)[0])
    assert "also planned for port 16102" in nodes[ROOT].skip
    assert f"also planned for port {ROOT}" in nodes[16102].skip


def test_the_router_override_never_names_a_node(setup):
    cfg, pm = setup(
        overrides=[{"match": "192.168.50.1", "sys_name": "aimesh-main"}],
        nodes=[(MAC_A, "192.168.50.101")],
    )
    nodes = by_port(plan_nodes(cfg, pm)[0])
    assert nodes[ROOT].hostname == "aimesh-main"
    assert nodes[16102].hostname == "aimesh-00000a"


# --- [onboard] hostname = "ip": the LibreNMS hostname is the node's LAN IP ---------


def test_ip_hostnames_name_each_node_by_the_ip_nodes_expected_reserves(setup):
    cfg, pm = setup(
        nodes=[(MAC_A, "192.168.50.101"), (MAC_B, "192.168.50.103")], hostname="ip"
    )
    nodes, warnings = plan_nodes(cfg, pm)
    assert [(n.port, n.role, n.hostname, n.served) for n in nodes] == [
        (ROOT, "root", "192.168.50.1", "aimesh-root"),
        (16102, "node", "192.168.50.101", "aimesh-00000a"),
        (16104, "node", "192.168.50.103", "aimesh-00000b"),
    ]
    assert [n.skip for n in nodes] == [None, None, None]
    assert warnings == []


def test_sysname_is_the_default_and_serves_the_hostname(setup):
    cfg, pm = setup(nodes=[(MAC_A, "192.168.50.101")], hostname="sysname")
    nodes = plan_nodes(cfg, pm)[0]
    assert [(n.hostname, n.served, n.sys_name) for n in nodes] == [
        ("aimesh-root", "aimesh-root", None),
        ("aimesh-00000a", "aimesh-00000a", None),
    ]


def test_an_override_name_is_still_the_served_sysname_in_ip_mode(setup):
    cfg, pm = setup(
        overrides=[
            {"match": "192.168.50.1", "sys_name": "aimesh-main"},
            {"match": MAC_B.upper(), "sys_name": "aimesh-den"},
        ],
        nodes=[(MAC_B, "192.168.50.102")],
        hostname="ip",
    )
    nodes = by_port(plan_nodes(cfg, pm)[0])
    assert (nodes[ROOT].hostname, nodes[ROOT].served) == ("192.168.50.1", "aimesh-main")
    assert (nodes[16103].hostname, nodes[16103].served) == (
        "192.168.50.102",
        "aimesh-den",
    )


def test_an_ip_override_with_a_port_names_its_node_by_that_ip(setup):
    cfg, pm = setup(
        overrides=[
            {"match": "192.168.50.103", "sys_name": "aimesh-loft", "port": 16150}
        ],
        nodes=[(MAC_C, "192.168.50.103", 16150)],
        hostname="ip",
    )
    node = by_port(plan_nodes(cfg, pm)[0])[16150]
    assert (node.hostname, node.served, node.skip) == (
        "192.168.50.103",
        "aimesh-loft",
        None,
    )


def test_a_node_outside_nodes_expected_has_no_ip_to_name_it_by(setup):
    cfg, pm = setup(nodes=[(MAC_A, "192.168.50.200")], hostname="ip")
    node = by_port(plan_nodes(cfg, pm)[0])[16112]
    assert node.hostname is None
    assert node.served == "aimesh-00000a"
    assert "nodes.expected" in node.skip


def test_the_root_needs_an_ip_for_asus_host_in_ip_mode(setup):
    cfg, pm = setup(host="router.asus.com", hostname="ip")
    (root,) = plan_nodes(cfg, pm)[0]
    assert root.hostname is None
    assert "asus.host" in root.skip


def test_excluded_nodes_stay_excluded_in_ip_mode(setup):
    cfg, pm = setup(
        overrides=[{"match": MAC_A, "exclude": True}],
        nodes=[(MAC_A, "192.168.50.101")],
        hostname="ip",
    )
    node = by_port(plan_nodes(cfg, pm)[0])[16102]
    assert (node.hostname, node.skip) == (None, "excluded by override")


def test_two_nodes_planned_at_one_ip_are_both_skipped(setup):
    cfg, pm = setup(
        overrides=[
            {"match": "192.168.50.101", "sys_name": "aimesh-twin", "port": 16150}
        ],
        nodes=[(MAC_A, "192.168.50.101"), (MAC_C, "192.168.50.240", 16150)],
        hostname="ip",
    )
    nodes = by_port(plan_nodes(cfg, pm)[0])
    assert "also planned for port 16150" in nodes[16102].skip
    assert "also planned for port 16102" in nodes[16150].skip
    assert nodes[16102].served == "aimesh-00000a"
