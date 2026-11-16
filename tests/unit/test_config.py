from pathlib import Path

import pytest

from aimesh_snmp_proxy.config import (
    DEFAULT_STATE_DIR,
    CollectorConfig,
    ConfigError,
    Override,
    default_sys_name,
    load_config,
)

EXPECTED = tuple(f"192.168.50.{octet}" for octet in range(101, 111))
MAC_A = "00:00:5e:00:53:0a"
MAC_B = "00:00:5e:00:53:0b"


def load(make_config, doc, env=None):
    return load_config(make_config(doc), env=env or {})


def raises(make_config, doc, pattern, env=None):
    with pytest.raises(ConfigError, match=pattern) as exc:
        load(make_config, doc, env)
    return str(exc.value)


# --- defaults and structure --------------------------------------------------


def test_minimal_config_gets_documented_defaults(make_config, base_config, tmp_path):
    cfg = load(make_config, base_config)
    assert cfg.source == tmp_path / "config.toml"
    assert cfg.state_dir == tmp_path / "state"
    assert cfg.ports_file == tmp_path / "state" / "ports.json"
    assert cfg.counters_file == tmp_path / "state" / "counters.json"
    assert cfg.lockout_file == tmp_path / "state" / "lockout.json"
    asus = cfg.asus
    assert (asus.host, asus.username, asus.port) == ("192.168.50.1", "admin", None)
    assert asus.use_ssl is True
    assert asus.password_file == tmp_path / "asus_password"
    assert asus.ca_file == tmp_path / "router.pem"
    snmp = cfg.snmp
    assert (snmp.bind, snmp.port_base, snmp.profile) == (
        "127.0.0.1",
        16101,
        "asuswrt-merlin",
    )
    assert snmp.community_file == tmp_path / "snmp_community"
    assert snmp.v3 is None
    assert cfg.nodes.expected == EXPECTED
    assert cfg.overrides == ()
    assert cfg.collector == CollectorConfig()
    assert (cfg.collector.mode, cfg.collector.stale_after_s) == ("root_only", 180)
    assert cfg.logging.level == "INFO"
    assert cfg.onboard is None


def test_node_ca_file_is_optional_and_resolves_like_ca_file(
    make_config, base_config, tmp_path
):
    assert load(make_config, base_config).asus.node_ca_file is None
    base_config["asus"]["node_ca_file"] = "asus_node_ca.pem"
    cfg = load(make_config, base_config)
    assert cfg.asus.node_ca_file == tmp_path / "asus_node_ca.pem"
    creds = {"CREDENTIALS_DIRECTORY": str(tmp_path / "creds")}
    cfg = load_config(make_config(base_config), env=creds)
    assert cfg.asus.node_ca_file == tmp_path / "creds" / "asus_node_ca.pem"


def test_state_dir_defaults_to_systemd_state_directory(make_config, base_config):
    del base_config["state_dir"]
    env = {"STATE_DIRECTORY": "/var/lib/aimesh:/var/lib/other"}
    assert load(make_config, base_config, env).state_dir == Path("/var/lib/aimesh")
    assert load(make_config, base_config).state_dir == DEFAULT_STATE_DIR


def test_state_dir_must_be_absolute(make_config, base_config):
    base_config["state_dir"] = "relative/state"
    raises(make_config, base_config, r"^state_dir: must be an absolute path")


def test_state_dir_inside_a_section_gets_a_hint(make_config, base_config):
    base_config["asus"]["state_dir"] = "/var/lib/x"
    raises(make_config, base_config, r"asus.state_dir: state_dir belongs at the top")


def test_missing_config_file(tmp_path):
    with pytest.raises(ConfigError, match=r"config file not found"):
        load_config(tmp_path / "nope.toml", env={})


def test_config_path_that_is_a_directory(tmp_path):
    with pytest.raises(ConfigError, match=r"cannot read config file"):
        load_config(tmp_path, env={})


def test_invalid_toml_never_echoes_content(make_config):
    path = make_config(text="[asus]\npassword = hunter2-secret\n")
    with pytest.raises(ConfigError, match=r"invalid TOML") as exc:
        load_config(path, env={})
    assert "hunter2" not in str(exc.value)


@pytest.mark.parametrize(
    ("table", "key", "hint"),
    [
        ("asus", "password", "password_file"),
        ("snmp", "community", "community_file"),
        ("v3", "auth_key", "auth_key_file"),
        ("v3", "priv_key", "priv_key_file"),
        ("onboard", "token", "token_file"),
    ],
)
def test_inline_secret_is_rejected_without_echo(
    make_config, base_config, v3_table, table, key, hint
):
    base_config["snmp"]["v3"] = v3_table
    base_config["onboard"] = {"token_file": "onboard_token"}
    target = v3_table if table == "v3" else base_config[table]
    target[key] = "hunter2-inline-secret"
    message = raises(
        make_config, base_config, f"inline secrets are not allowed; use {hint}"
    )
    assert "hunter2" not in message


def test_unknown_key_is_rejected(make_config, base_config):
    base_config["snmp"]["bnid"] = "127.0.0.1"
    raises(make_config, base_config, r"snmp.bnid: unknown key")


@pytest.mark.parametrize("section", ["extra", "node"])
def test_unknown_section_is_rejected(make_config, base_config, section):
    base_config[section] = {"x": 1}
    raises(make_config, base_config, rf"^{section}: unknown key")


@pytest.mark.parametrize("section", ["asus", "snmp"])
def test_required_sections(make_config, base_config, section):
    del base_config[section]
    raises(make_config, base_config, rf"^{section}: required")


def test_section_must_be_a_table(make_config, base_config):
    base_config["collector"] = "fast"
    raises(make_config, base_config, r"collector: expected a table")


# --- [asus] ------------------------------------------------------------------


@pytest.mark.parametrize("key", ["host", "username", "password_file", "ca_file"])
def test_required_asus_keys(make_config, base_config, key):
    del base_config["asus"][key]
    raises(make_config, base_config, rf"asus.{key}: required")


def test_plain_http_is_refused(make_config, base_config):
    base_config["asus"]["use_ssl"] = False
    raises(make_config, base_config, r"asus.use_ssl: must be true; plain HTTP sends")


def test_allow_cleartext_no_longer_exists(make_config, base_config):
    base_config["asus"]["allow_cleartext"] = True
    raises(make_config, base_config, r"asus.allow_cleartext: unknown key")


@pytest.mark.parametrize("host", ["router.asus.com", "192.168.50.1", "fd00::6"])
def test_valid_router_hosts(make_config, base_config, host):
    base_config["asus"]["host"] = host
    assert load(make_config, base_config).asus.host == host


@pytest.mark.parametrize("host", ["http://192.168.50.1", "", "bad host", "-x.lan"])
def test_invalid_router_hosts(make_config, base_config, host):
    base_config["asus"]["host"] = host
    raises(make_config, base_config, r"asus.host: expected a hostname or IP")


def test_router_port_and_username_checks(make_config, base_config):
    base_config["asus"]["port"] = 8443
    assert load(make_config, base_config).asus.port == 8443
    base_config["asus"]["port"] = 0
    raises(make_config, base_config, r"asus.port: must be between 1 and 65535")
    base_config["asus"]["port"] = 8443
    base_config["asus"]["username"] = "ad\nmin"
    raises(make_config, base_config, r"asus.username: expected one non-empty line")


# --- [nodes] -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("expected", "addresses"),
    [
        ("192.168.50.101-110", EXPECTED),
        ("192.168.50.101-192.168.50.103", EXPECTED[:3]),
        ("192.168.50.101", EXPECTED[:1]),
        (
            ["192.168.50.101", "192.168.50.200 - 201"],
            ("192.168.50.101", "192.168.50.200", "192.168.50.201"),
        ),
        ([], ()),
    ],
)
def test_expected_addresses(make_config, base_config, expected, addresses):
    base_config["nodes"]["expected"] = expected
    assert load(make_config, base_config).nodes.expected == addresses


def test_nodes_section_is_optional(make_config, base_config):
    del base_config["nodes"]
    assert load(make_config, base_config).nodes.expected == ()


@pytest.mark.parametrize(
    ("expected", "message"),
    [
        ("192.168.50.110-101", "expected IPv4 addresses or ranges"),
        ("192.168.50.101-300", "expected IPv4 addresses or ranges"),
        ("192.168.50.101-", "expected IPv4 addresses or ranges"),
        ("nonsense", "expected IPv4 addresses or ranges"),
        ("198.18.0.0-198.18.1.10", "expected IPv4 addresses or ranges"),
        (["192.168.50.101", "192.168.50.100-102"], "lists an address twice"),
        (161, "expected a list, got integer"),
        ([161], "expected a list of strings"),
    ],
)
def test_invalid_expected_addresses(make_config, base_config, expected, message):
    base_config["nodes"]["expected"] = expected
    raises(make_config, base_config, rf"nodes.expected: {message}")


def test_too_many_expected_addresses(make_config, base_config):
    base_config["nodes"]["expected"] = [
        "198.18.0.0-198.18.0.200",
        "198.18.1.0-198.18.1.200",
    ]
    raises(make_config, base_config, r"nodes.expected: at most 255 addresses")


# --- [snmp] ------------------------------------------------------------------


@pytest.mark.parametrize("bind", ["0.0.0.0", "::1", "192.168.50.10", "localhost"])
def test_snmp_bind_accepts_only_loopback_ipv4(make_config, base_config, bind):
    base_config["snmp"]["bind"] = bind
    raises(make_config, base_config, r"snmp.bind: must be 127.0.0.1")


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("port_base", "16101", "snmp.port_base: expected an integer, got string"),
        ("port_base", True, "snmp.port_base: expected an integer, got boolean"),
        ("port_base", 1000, "snmp.port_base: must be between 1024 and 65280"),
        ("port_base", 65281, "snmp.port_base: must be between 1024 and 65280"),
        ("bind", 127, "snmp.bind: expected a string, got integer"),
        ("profile", "UPPER", "snmp.profile: expected a profile name"),
        ("community_file", "", "snmp.community_file: expected a file path"),
    ],
)
def test_invalid_snmp_fields(make_config, base_config, key, value, message):
    base_config["snmp"][key] = value
    raises(make_config, base_config, message)


def test_some_snmp_auth_is_required(make_config, base_config):
    del base_config["snmp"]["community_file"]
    raises(make_config, base_config, r"snmp: set community_file \(v2c\) or add")


def test_v3_alone_is_enough(make_config, base_config, v3_table, tmp_path):
    del base_config["snmp"]["community_file"]
    base_config["snmp"]["v3"] = v3_table
    snmp = load(make_config, base_config).snmp
    assert snmp.community_file is None
    assert (snmp.v3.user, snmp.v3.auth, snmp.v3.priv) == (
        "librenms",
        "SHA-256",
        "AES-128",
    )
    assert snmp.v3.auth_key_file == tmp_path / "snmp_auth_key"


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("auth", "MD5", "snmp.v3.auth: must be one of SHA-1, SHA-224"),
        ("priv", "DES", "snmp.v3.priv: must be one of AES-128"),
        ("user", "bad user", "snmp.v3.user: expected 1-32"),
        ("user", "x" * 33, "snmp.v3.user: expected 1-32"),
    ],
)
def test_invalid_v3_fields(make_config, base_config, v3_table, key, value, message):
    base_config["snmp"]["v3"] = {**v3_table, key: value}
    raises(make_config, base_config, message)


def test_v3_protocol_names_are_case_insensitive(make_config, base_config, v3_table):
    base_config["snmp"]["v3"] = {**v3_table, "auth": "sha-512", "priv": "aes-128"}
    v3 = load(make_config, base_config).snmp.v3
    assert (v3.auth, v3.priv) == ("SHA-512", "AES-128")


def test_v3_needs_both_key_files(make_config, base_config, v3_table):
    del v3_table["priv_key_file"]
    base_config["snmp"]["v3"] = v3_table
    raises(make_config, base_config, r"snmp.v3.priv_key_file: required")


# --- [[override]] ------------------------------------------------------------


def test_overrides_are_parsed_and_normalized(make_config, base_config):
    base_config["override"] = [
        {"match": "192.168.50.101", "sys_name": "aimesh-hall", "login": False},
        {"match": "00-00-5E-00-53-0B", "port": 16120, "location": "Attic"},
        {"match": "192.168.50.110", "exclude": True},
    ]
    assert load(make_config, base_config).overrides == (
        Override(match="192.168.50.101", sys_name="aimesh-hall", login=False),
        Override(match=MAC_B, port=16120, location="Attic"),
        Override(match="192.168.50.110", exclude=True),
    )


def test_an_override_can_pin_a_node_certificate(make_config, base_config, tmp_path):
    base_config["override"] = [
        {"match": "192.168.50.104", "ca_file": "node-104.pem"},
        {"match": MAC_A, "ca_file": "/etc/pins/node-a.pem"},
        {"match": MAC_B},
    ]
    pins = [o.ca_file for o in load(make_config, base_config).overrides]
    assert pins == [tmp_path / "node-104.pem", Path("/etc/pins/node-a.pem"), None]
    creds = {"CREDENTIALS_DIRECTORY": str(tmp_path / "creds")}
    cfg = load_config(make_config(base_config), env=creds)
    assert cfg.overrides[0].ca_file == tmp_path / "creds" / "node-104.pem"


def test_override_for_prefers_mac_over_ip(make_config, base_config):
    base_config["override"] = [
        {"match": "192.168.50.101", "sys_name": "by-ip"},
        {"match": MAC_A, "sys_name": "by-mac"},
    ]
    cfg = load(make_config, base_config)
    assert cfg.override_for(MAC_A.upper(), "192.168.50.101").sys_name == "by-mac"
    assert cfg.override_for(MAC_B, "192.168.50.101").sys_name == "by-ip"
    assert cfg.override_for(MAC_B, "192.168.50.102") is None
    assert cfg.override_for(MAC_B, None) is None
    assert cfg.override_for(MAC_B, "not-an-ip") is None


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            [{"match": MAC_A}, {"match": MAC_A.upper()}],
            r"override\[1\]: duplicate match \(same as override\[0\]\)",
        ),
        (
            [
                {"match": MAC_A, "sys_name": "Office"},
                {"match": MAC_B, "sys_name": "office"},
            ],
            r"override\[1\]: duplicate sys_name",
        ),
        (
            [{"match": MAC_A, "port": 16120}, {"match": MAC_B, "port": 16120}],
            r"override\[1\]: duplicate port",
        ),
        ([{"match": "nonsense"}], r"override\[0\].match: expected an IPv4 or MAC"),
        ([{"sys_name": "x"}], r"override\[0\].match: required"),
        (
            [{"match": MAC_A, "sys_name": "bad name!"}],
            r"override\[0\].sys_name: expected 1-63",
        ),
        (
            [{"match": MAC_A, "port": 16101}],
            r"override\[0\].port: must be between 16102 and 16356",
        ),
        (
            [{"match": MAC_A, "port": 16357}],
            r"override\[0\].port: must be between 16102 and 16356",
        ),
        (
            [{"match": MAC_A, "location": "x" * 256}],
            r"override\[0\].location: at most 255 characters",
        ),
        (
            [{"match": MAC_A, "exclude": True, "sys_name": "x"}],
            r"override\[0\]: an excluded node takes no other settings",
        ),
        ([{"match": MAC_A, "colour": "red"}], r"override\[0\].colour: unknown key"),
        (
            [{"match": MAC_A, "exclude": True, "ca_file": "node.pem"}],
            r"override\[0\]: an excluded node takes no other settings",
        ),
        (
            [{"match": MAC_A, "login": False, "ca_file": "node.pem"}],
            r"override\[0\].ca_file: pins a node session, which login = false",
        ),
    ],
)
def test_invalid_overrides(make_config, base_config, overrides, message):
    base_config["override"] = overrides
    text = raises(make_config, base_config, message)
    assert MAC_A not in text.lower()


def test_override_must_be_an_array_of_tables(make_config, base_config):
    base_config["override"] = "x"
    raises(make_config, base_config, r"override: expected \[\[override\]\] tables")


def test_default_sys_name_uses_last_six_hex_digits():
    assert default_sys_name(MAC_A) == "aimesh-00530a"


def test_sys_names_are_unique(make_config, base_config):
    base_config["override"] = [
        {"match": "192.168.50.101", "sys_name": "aimesh-hall"},
        {"match": "192.168.50.110", "exclude": True},
        {"match": "00:00:5e:00:53:0c", "sys_name": "AIMESH-00530D"},
    ]
    cfg = load(make_config, base_config)
    nodes = [
        ("00:00:5e:00:53:01", "192.168.50.1"),
        (MAC_A, "192.168.50.101"),
        (MAC_B, "192.168.50.102"),
        ("02:11:22:00:53:0b", "192.168.50.103"),
        ("00:00:5e:00:53:0c", "192.168.50.104"),
        ("00:00:5e:00:53:0d", "192.168.50.105"),
        ("00:00:5e:00:53:0e", "192.168.50.110"),
    ]
    assert cfg.sys_names(nodes) == {
        "00:00:5e:00:53:01": "aimesh-root",
        MAC_A: "aimesh-hall",
        MAC_B: "aimesh-00005e00530b",
        "02:11:22:00:53:0b": "aimesh-02112200530b",
        "00:00:5e:00:53:0c": "AIMESH-00530D",
        "00:00:5e:00:53:0d": "aimesh-00005e00530d",
    }


def test_sys_names_reject_bad_macs(make_config, base_config):
    with pytest.raises(ValueError, match="not a MAC address"):
        load(make_config, base_config).sys_names([("nonsense", None)])


# --- [collector], [logging], [onboard] ----------------------------------------


def test_collector_settings(make_config, base_config):
    base_config["collector"] = {
        "mode": "per_node",
        "stale_after_s": 240,
        "metrics_interval_s": 30.5,
        "topology_interval_s": 600,
        "request_timeout_s": 5,
    }
    c = load(make_config, base_config).collector
    assert (c.mode, c.stale_after_s, c.metrics_interval_s) == ("per_node", 240, 30.5)
    assert (c.topology_interval_s, c.request_timeout_s) == (600, 5)


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({"mode": "all"}, "collector.mode: must be one of root_only, per_node"),
        ({"stale_after_s": 0}, "collector.stale_after_s: must be a positive number"),
        ({"stale_after_s": "x"}, "collector.stale_after_s: expected a number"),
        ({"stale_after_s": 60}, "collector.stale_after_s: must exceed"),
        ({"metrics_interval_s": 170}, "collector.stale_after_s: must exceed"),
    ],
)
def test_invalid_collector_settings(make_config, base_config, values, message):
    base_config["collector"] = values
    raises(make_config, base_config, message)


def test_logging_level_is_normalized(make_config, base_config):
    base_config["logging"] = {"level": "debug"}
    assert load(make_config, base_config).logging.level == "DEBUG"
    base_config["logging"] = {"level": "UNSAFE"}
    raises(make_config, base_config, r"logging.level: must be one of DEBUG")


def test_onboard_section(make_config, base_config, tmp_path):
    base_config["onboard"] = {"token_file": "onboard_token", "ca_file": "librenms.pem"}
    onboard = load(make_config, base_config).onboard
    assert onboard.url == "http://127.0.0.1"
    assert onboard.token_file == tmp_path / "onboard_token"
    assert onboard.ca_file == tmp_path / "librenms.pem"
    base_config["onboard"]["url"] = "https://librenms.example.com"
    assert load(make_config, base_config).onboard.url == "https://librenms.example.com"


def test_onboard_hostname_defaults_to_the_served_sysname(make_config, base_config):
    base_config["onboard"] = {"token_file": "onboard_token"}
    assert load(make_config, base_config).onboard.hostname == "sysname"


@pytest.mark.parametrize("value", ["sysname", "ip"])
def test_onboard_hostname_takes_sysname_or_ip(make_config, base_config, value):
    base_config["onboard"] = {"hostname": value}
    assert load(make_config, base_config).onboard.hostname == value


@pytest.mark.parametrize("value", ["IP", "fqdn", "", "mac"])
def test_onboard_hostname_refuses_anything_else(make_config, base_config, value):
    base_config["onboard"] = {"hostname": value}
    raises(make_config, base_config, r'onboard.hostname: must be "sysname" or "ip"')


def test_onboard_hostname_must_be_a_string(make_config, base_config):
    base_config["onboard"] = {"hostname": 7}
    raises(make_config, base_config, "onboard.hostname: expected a string")


def test_onboard_hostname_comes_from_the_environment_too(make_config, base_config):
    base_config["onboard"] = {"token_file": "onboard_token"}
    env = {"AIMESH_PROXY__ONBOARD__HOSTNAME": "ip"}
    assert load(make_config, base_config, env).onboard.hostname == "ip"


def test_onboard_files_are_optional_until_onboard_runs(make_config, base_config):
    base_config["onboard"] = {"url": "https://192.168.50.10"}
    onboard = load(make_config, base_config).onboard
    assert (onboard.token_file, onboard.ca_file) == (None, None)


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("ftp://127.0.0.1", "onboard.url: expected an http or https URL"),
        ("127.0.0.1", "onboard.url: expected an http or https URL"),
        ("http://[::1", "onboard.url: expected an http or https URL"),
        ("https://u:hunter2-pw@host", "onboard.url: must not contain credentials"),
    ],
)
def test_invalid_onboard_url(make_config, base_config, url, message):
    base_config["onboard"] = {"url": url, "token_file": "onboard_token"}
    assert "hunter2" not in raises(make_config, base_config, message)


# --- file paths --------------------------------------------------------------


def test_secret_paths_resolve_against_credentials_directory(make_config, base_config):
    env = {"CREDENTIALS_DIRECTORY": "/run/credentials/aimesh.service"}
    base_config["asus"]["ca_file"] = "/etc/aimesh/router.pem"
    cfg = load(make_config, base_config, env)
    creds = Path("/run/credentials/aimesh.service")
    assert cfg.asus.password_file == creds / "asus_password"
    assert cfg.snmp.community_file == creds / "snmp_community"
    assert cfg.asus.ca_file == Path("/etc/aimesh/router.pem")


def test_empty_file_path_is_rejected(make_config, base_config):
    base_config["asus"]["password_file"] = ""
    raises(make_config, base_config, r"asus.password_file: expected a file path")


def test_secret_files_lists_every_configured_secret(
    make_config, base_config, v3_table, tmp_path
):
    base_config["snmp"]["v3"] = v3_table
    base_config["onboard"] = {"token_file": "onboard_token"}
    cfg = load(make_config, base_config)
    daemon = {
        "asus.password_file": tmp_path / "asus_password",
        "snmp.community_file": tmp_path / "snmp_community",
        "snmp.v3.auth_key_file": tmp_path / "snmp_auth_key",
        "snmp.v3.priv_key_file": tmp_path / "snmp_priv_key",
    }
    assert cfg.secret_files() == daemon
    assert cfg.secret_files(onboard=True) == {
        **daemon,
        "onboard.token_file": tmp_path / "onboard_token",
    }


def test_secret_files_for_v3_only(make_config, base_config, v3_table, tmp_path):
    del base_config["snmp"]["community_file"]
    base_config["snmp"]["v3"] = v3_table
    assert list(load(make_config, base_config).secret_files()) == [
        "asus.password_file",
        "snmp.v3.auth_key_file",
        "snmp.v3.priv_key_file",
    ]


# --- environment overrides ---------------------------------------------------


def test_env_overrides_scalars_lists_and_paths(make_config, base_config, v3_table):
    base_config["snmp"]["v3"] = v3_table
    env = {
        "AIMESH_PROXY__STATE_DIR": "/var/lib/elsewhere",
        "AIMESH_PROXY__ASUS__HOST": "192.168.50.2",
        "AIMESH_PROXY__ASUS__PORT": "8443",
        "AIMESH_PROXY__ASUS__USE_SSL": "yes",
        "AIMESH_PROXY__NODES__EXPECTED": "192.168.50.101-102, 192.168.50.110,",
        "AIMESH_PROXY__SNMP__PORT_BASE": "17000",
        "AIMESH_PROXY__SNMP__V3__AUTH_KEY_FILE": "/run/secrets/auth",
        "AIMESH_PROXY__COLLECTOR__STALE_AFTER_S": "200.5",
        "AIMESH_PROXY__LOGGING__LEVEL": "warning",
        "UNRELATED": "ignored",
    }
    cfg = load(make_config, base_config, env)
    assert cfg.state_dir == Path("/var/lib/elsewhere")
    assert (cfg.asus.host, cfg.asus.port, cfg.asus.use_ssl) == (
        "192.168.50.2",
        8443,
        True,
    )
    assert cfg.nodes.expected == ("192.168.50.101", "192.168.50.102", "192.168.50.110")
    assert cfg.snmp.port_base == 17000
    assert cfg.snmp.v3.auth_key_file == Path("/run/secrets/auth")
    assert cfg.collector.stale_after_s == 200.5
    assert cfg.logging.level == "WARNING"


def test_env_creates_missing_section(make_config, base_config):
    env = {"AIMESH_PROXY__COLLECTOR__MODE": "per_node"}
    assert load(make_config, base_config, env).collector.mode == "per_node"


@pytest.mark.parametrize(
    ("var", "value", "message"),
    [
        (
            "AIMESH_PROXY__ASUS__PASSWORD",
            "hunter2-env",
            "inline secrets are not allowed",
        ),
        (
            "AIMESH_PROXY__SNMP__COMMUNITY",
            "hunter2-env",
            "inline secrets are not allowed",
        ),
        ("AIMESH_PROXY__SNMP__PORT_BASE", "hunter2-env", "expected an integer"),
        ("AIMESH_PROXY__ASUS__USE_SSL", "hunter2-env", "expected true or false"),
        ("AIMESH_PROXY__COLLECTOR__STALE_AFTER_S", "nan", "expected a number"),
        ("AIMESH_PROXY__COLLECTOR__STALE_AFTER_S", "soon", "expected a number"),
        ("AIMESH_PROXY__STATE_DIR", "relative", "must be an absolute path"),
        ("AIMESH_PROXY__OVERRIDE__0__MATCH", "x", r"\[\[override\]\] entries cannot"),
        ("AIMESH_PROXY__BOGUS__KEY", "x", "unknown section 'bogus'"),
        ("AIMESH_PROXY__STATE_DIR__X", "x", "unknown section 'state_dir'"),
        ("AIMESH_PROXY__ASUS", "x", "expected AIMESH_PROXY__<SECTION>__<KEY>"),
        ("AIMESH_PROXY__ASUS____HOST", "x", "expected AIMESH_PROXY__<SECTION>__<KEY>"),
        ("AIMESH_PROXY__SNMP__V3", "x", "snmp.v3 .*: expected a table"),
        ("AIMESH_PROXY__ASUS__HOST__X", "x", "asus.host is not a table"),
    ],
)
def test_bad_env_override_names_variable_not_value(
    make_config, base_config, var, value, message
):
    text = raises(make_config, base_config, message, {var: value})
    assert "hunter2" not in text


def test_env_cannot_replace_a_table(make_config, base_config, v3_table):
    base_config["snmp"]["v3"] = v3_table
    env = {"AIMESH_PROXY__SNMP__V3": "x"}
    raises(make_config, base_config, r"cannot replace table snmp.v3", env)


def test_env_type_error_names_the_variable(make_config, base_config):
    env = {"AIMESH_PROXY__SNMP__PORT_BASE": "abc"}
    raises(make_config, base_config, r"\(from \$AIMESH_PROXY__SNMP__PORT_BASE\)", env)


def test_default_env_is_process_environment(make_config, base_config, monkeypatch):
    monkeypatch.setenv("AIMESH_PROXY__SNMP__PORT_BASE", "18000")
    assert load_config(make_config(base_config)).snmp.port_base == 18000


# --- TOML value types ----------------------------------------------------------


def test_non_boolean_toml_value_is_named(make_config, base_config):
    base_config["asus"]["use_ssl"] = "yes"
    raises(
        make_config, base_config, r"asus.use_ssl: expected true or false, got string"
    )


def test_toml_dates_are_named_in_type_errors(make_config, base_config):
    base_config["snmp"]["port_base"] = 16101
    path = make_config(base_config)
    path.write_text(
        path.read_text().replace("port_base = 16101", "port_base = 1979-05-27")
    )
    with pytest.raises(
        ConfigError, match=r"snmp.port_base: expected an integer, got date"
    ):
        load_config(path, env={})


# --- the root router -----------------------------------------------------------

ROOT_MAC = "00:00:5e:00:53:01"


def test_root_ip_is_the_router_host_when_it_is_an_address(make_config, base_config):
    assert load(make_config, base_config).root_ip == "192.168.50.1"
    base_config["asus"]["host"] = "router.asus.com"
    assert load(make_config, base_config).root_ip is None


def test_root_sys_name_defaults_to_aimesh_root(make_config, base_config):
    assert load(make_config, base_config).root_sys_name() == "aimesh-root"
    base_config["override"] = [{"match": "192.168.50.1", "sys_name": "gateway"}]
    assert load(make_config, base_config).root_sys_name() == "gateway"
    base_config["override"] = [{"match": "192.168.50.1", "exclude": True}]
    assert load(make_config, base_config).root_sys_name() is None


def test_sys_names_name_the_root(make_config, base_config):
    cfg = load(make_config, base_config)
    assert cfg.sys_names([(ROOT_MAC, "192.168.50.1")]) == {ROOT_MAC: "aimesh-root"}
    assert cfg.sys_names([(ROOT_MAC, None)]) == {ROOT_MAC: "aimesh-005301"}
    assert cfg.sys_names([(ROOT_MAC, None)], root_mac=ROOT_MAC.upper()) == {
        ROOT_MAC: "aimesh-root"
    }


def test_root_override_by_mac_renames_or_excludes_it(make_config, base_config):
    base_config["override"] = [{"match": ROOT_MAC, "sys_name": "gateway"}]
    cfg = load(make_config, base_config)
    assert cfg.sys_names([(ROOT_MAC, "192.168.50.1")]) == {ROOT_MAC: "gateway"}
    base_config["override"] = [{"match": ROOT_MAC, "exclude": True}]
    cfg = load(make_config, base_config)
    assert cfg.sys_names([(ROOT_MAC, "192.168.50.1")]) == {}


def test_root_name_yields_to_a_mac_override_that_claims_it(make_config, base_config):
    base_config["override"] = [{"match": MAC_A, "sys_name": "AIMESH-ROOT"}]
    cfg = load(make_config, base_config)
    names = cfg.sys_names([(ROOT_MAC, "192.168.50.1"), (MAC_A, "192.168.50.101")])
    assert names == {MAC_A: "AIMESH-ROOT", ROOT_MAC: "aimesh-00005e005301"}


@pytest.mark.parametrize(
    ("override", "message"),
    [
        (
            {"match": "192.168.50.101", "sys_name": "Aimesh-Root"},
            r"override\[0\].sys_name: aimesh-root is reserved for the root router",
        ),
    ],
)
def test_root_reservations_are_enforced(make_config, base_config, override, message):
    base_config["override"] = [override]
    raises(make_config, base_config, message)
