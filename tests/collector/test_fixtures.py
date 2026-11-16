import json

import pytest

from aimesh_snmp_proxy.collector.fixtures import Raw, scrub

CANARIES = {
    "psk": "canary-psk-Wifi-7781",
    "wg": "canary-wg-private-key-3341",
    "admin": "canary-http-passwd-9921",
    "token": "canary-asus-token-1177",
    "wps": "canary-wps-12345670",
    "serial": "canary-serial-R8X0001",
    "host": "canary-hostname-kitchen-ipad",
    "ssid": "canary-ssid-HomeNet",
    "ovpn": "canary-openvpn-pass-4417",
    "alias": "canary-node-alias-Bedroom",
    "client_ip": "192.168.50.237",
    "client_mac": "00:00:5E:00:53:EE",
}


def raw(endpoint, body, query=None, request=""):
    payload = json.dumps(body) if not isinstance(body, str | bytes) else body
    data = payload.encode() if isinstance(payload, str) else payload
    return Raw(endpoint, query or {}, request, data)


def js(variables):
    return "\n".join(f"{k} = {json.dumps(v)};" for k, v in variables.items())


def planted():
    c = CANARIES
    node = {
        "mac": "00:00:5E:00:53:01",
        "alias": c["alias"],
        "model_name": "RT-AX88U",
        "fwver": "3.0.0.4.388.4_0",
        "ip": "192.168.50.1",
        "online": "1",
        "level": "0",
        "re_path": "0",
        "ap2g": "00:00:5E:00:53:10",
        "ap2g_ssid": c["ssid"],
        "pap5g_ssid": c["ssid"],
        "band_info": {"0": {"unit": 0, "secret": c["psk"]}},
        "config": {
            "wireless": {
                "wl0_radio": "1",
                "wl0_wpa_psk": c["psk"],
                "wl0_ssid": c["ssid"],
            },
            "prefer_ap": {"amas_wlc_target_bssid": c["psk"]},
        },
        "model_display": "RT psk=" + c["psk"],
        "product_id": "RT psk=" + c["psk"],
        "ui_model_name": "x" * 200,
    }
    client = {
        "mac": c["client_mac"],
        "name": c["host"],
        "nickName": c["host"],
        "ip": c["client_ip"],
        "ssid": c["ssid"],
        "isOnline": "1",
        "isWL": "2",
        "rssi": "-46",
        "curTx": "866",
        "curRx": "650",
        "amesh_papMac": "00:00:5E:00:53:01",
        "mlo_links": {
            "5G1": {"mac": c["client_mac"], "rssi": "-63", "name": c["host"]}
        },
    }
    return [
        raw(
            "appGet.cgi",
            {
                "label_mac": "00:00:5E:00:53:01",
                "productid": "RT-AX88U",
                "secret_code": c["wps"],
                "serial_no": c["serial"],
                "http_passwd": c["admin"],
                "wl0_wpa_psk": c["psk"],
                "wgs_priv": c["wg"],
                "asus_token": c["token"],
                "get_ui_support": {"amas": 1, c["psk"]: 1},
                "uptime": "Sat, 01 Aug 2015 03:09:22 +0200(4162 secs since boot)",
                "cpu_usage": {"cpu1_total": "52557468", "cpu1_note": c["psk"]},
                "memory_usage": {"mem_total": "1048576", "mem_free": "235464"},
                "wl_control_channel": ["6", "100", c["psk"]],
                "get_clientlist": {
                    c["client_mac"]: client,
                    "maclist": [c["client_mac"]],
                },
            },
        ),
        raw(
            "ajax_onboarding.asp",
            js(
                {
                    "get_cfg_clientlist": [[node]],
                    "get_onboardinglist": [{c["client_mac"]: {"name": c["host"]}}],
                    "get_allclientlist": [{"x": {"ip": c["client_ip"]}}],
                    "get_onboardingstatus": [{"cfg_ready": "1", "cfg_note": c["psk"]}],
                }
            ),
        ),
        raw(
            "ajax_coretmp.asp",
            js({"curr_coreTmp_wl0_raw": "44&deg;C", "curr_cpuTemp": "65.514"}),
        ),
        raw(
            "get_diag_content_data.cgi",
            {"contents": [["5", "26"]]},
            query={
                "ts": "1700000000",
                "filter": "node_mac>txt>00:00:5E:00:53:01>0",
                "db": "sys_detect",
            },
        ),
        raw(
            "get_diag_wifi_traffic.cgi",
            {"data": {"rx": 1, "tx": 2, "hint": c["psk"]}, "error_status": 200},
            query={"node_mac": "00:00:5E:00:53:01", "band_mac": "00:00:5E:00:53:10"},
        ),
        raw("ajax_vpn_status.asp", js({"vpn_server_password": c["ovpn"]})),
        raw("appGet.cgi", "not json at all " + c["token"]),
        raw("get_diag_eth_traffic.cgi", b"\xff\xfe" + c["admin"].encode()),
    ]


def test_canaries_never_survive_the_scrubber():
    text = json.dumps(scrub(planted()))
    for name, canary in CANARIES.items():
        assert canary.lower() not in text.lower(), name


def test_scrubbed_fixture_keeps_what_the_collector_needs():
    doc = scrub(planted())
    appget = doc["appget"]
    assert appget["productid"] == "RT-AX88U"
    assert appget["get_ui_support"] == {"amas": 1}
    assert appget["wl_control_channel"] == ["6", "100"]
    clients = appget["get_clientlist"]
    (alias,) = clients
    assert clients[alias]["curTx"] == "866"
    assert clients[alias]["mac"] == alias
    node = doc["pages"]["ajax_onboarding.asp"]["get_cfg_clientlist"][0][0]
    assert node["config"] == {"wireless": {"wl0_radio": "1"}}
    assert node["band_info"] == {"0": {"unit": 0}}
    assert "model_display" not in node
    assert "ui_model_name" not in node  # too long to be a model name
    assert doc["pages"]["ajax_onboarding.asp"]["get_onboardinglist"] == [{}]
    assert doc["pages"]["ajax_coretmp.asp"]["curr_coreTmp_wl0_raw"] == "44&deg;C"
    assert "ajax_vpn_status.asp" not in doc["pages"]


def test_macs_are_pseudonymised_consistently_everywhere():
    doc = scrub(planted())
    root = doc["appget"]["label_mac"]
    assert root != "00:00:5E:00:53:01"
    node = doc["pages"]["ajax_onboarding.asp"]["get_cfg_clientlist"][0][0]
    assert node["mac"] == root
    (client,) = doc["appget"]["get_clientlist"].values()
    assert client["amesh_papMac"] == root
    diag, wifi = doc["queries"]
    assert diag["query"] == {"filter": f"node_mac>txt>{root}>0"}
    assert wifi["query"]["node_mac"] == root
    assert wifi["query"]["band_mac"] == node["ap2g"]
    assert wifi["reply"] == {"data": {"rx": 1, "tx": 2}, "error_status": 200}


def test_duplicate_queries_collapse():
    entries = planted()
    doc = scrub(entries + entries)
    assert len(doc["queries"]) == 2


@pytest.mark.parametrize(
    "value", ["", "00:00:5e:00:53:01", "00-00-5E-00-53-01", "nonsense"]
)
def test_mac_values_keep_blank_and_drop_garbage(value):
    entry = raw("appGet.cgi", {"label_mac": value})
    got = scrub([entry])["appget"]
    if value == "nonsense":
        assert "label_mac" not in got
    elif value == "":
        assert got["label_mac"] == ""
    else:
        assert got["label_mac"].replace("-", ":").lower().startswith("02:00:00:00:")
