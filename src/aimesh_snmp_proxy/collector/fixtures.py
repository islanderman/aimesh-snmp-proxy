"""Capture and scrub router replies into test fixtures (``discover --fixtures``, H4).

The scrubber is a key allowlist: a value survives only when its key is listed
for its place in the reply and the value has the expected shape (number,
flag, MAC, short model text). Everything else is dropped: PSKs, tokens,
passwords, SSIDs, hostnames, client names and IPs. Every MAC, node or
client, is replaced by a stable ``02:00:00:00:xx:yy`` alias, so relations
survive but no real address does. Login and logout exchanges are never kept.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

from asusrouter.modules.endpoint import AREndpoint
from asusrouter.tools.readers import read_js_variables, read_json_content

from aimesh_snmp_proxy.collector.session import quiet_library_logging
from aimesh_snmp_proxy.model import normalize_mac

FIXTURE_FORMAT = 1
FIXTURE_FILE = "fixture.json"


@dataclass(frozen=True)
class Raw:
    """One allowed read exchange: endpoint, query, request body, reply bytes."""

    endpoint: str
    query: dict[str, str]
    request: str
    body: bytes


class FixtureRecorder:
    """Client middleware keeping raw read replies; it runs after the guard."""

    _SKIP = frozenset({AREndpoint.LOGIN.value, AREndpoint.LOGOUT.value})

    def __init__(self) -> None:
        self.entries: list[Raw] = []

    async def __call__(self, req: Any, handler: Any) -> Any:
        resp = await handler(req)
        endpoint = req.url.path.lstrip("/")
        if endpoint not in self._SKIP and resp.status == 200:
            body = await resp.read()  # aiohttp caches it for the library's read
            request = req.body.decode(errors="replace") if req.body else ""
            self.entries.append(
                Raw(endpoint, dict(req.url.query), unquote(request), body)
            )
        return resp


# --- validators -------------------------------------------------------------------


class _NotAllowedError(Exception):
    """The value is not allowlisted here."""


class MacAliases:
    """Real MAC -> stable fake MAC, case style kept, for one capture."""

    def __init__(self) -> None:
        self._map: dict[str, str] = {}

    def alias(self, text: str) -> str:
        mac = normalize_mac(text)
        if mac is None:
            raise _NotAllowedError
        if mac not in self._map:
            n = len(self._map) + 1
            self._map[mac] = f"02:00:00:00:{n >> 8 & 0xFF:02x}:{n & 0xFF:02x}"
        fake = self._map[mac]
        return fake.upper() if text == text.upper() else fake


Validator = Callable[[Any, MacAliases], Any]
_INT = re.compile(r"-?\d{1,12}")
_NUM = re.compile(r"-?\d{1,12}(?:\.\d{1,6})?")
_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._+()/-]{0,47}")
_SAFE_KEY = re.compile(r"[A-Za-z0-9_]{1,32}")
_PORT_LABEL = re.compile(r"[A-Za-z0-9 _-]{1,16}")
_UPTIME = re.compile(r"[A-Za-z0-9 ,:+()-]{1,80}")
_TEMP = re.compile(r"-?\d{1,3}(?:\.\d{1,3})?&deg;C|<i>disabled</i>")
_DURATION = re.compile(r"\d{1,6}:\d{2}:\d{2}")
_BANDS = re.compile(r"[0-9a-z&#;]{1,64}")
_FEATURES = re.compile(r"[A-Za-z0-9_ .-]{0,4096}")
_LINK_RATE = re.compile(r"[A-Za-z]")
_FILTER = re.compile(r"node_mac>txt>([0-9A-Fa-f:-]{12,17})>0")


def mac(value: Any, macs: MacAliases) -> str:
    if value == "":
        return ""
    if not isinstance(value, str):
        raise _NotAllowedError
    return macs.alias(value)


def integer(value: Any, macs: MacAliases) -> Any:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if value == "" or (isinstance(value, str) and _INT.fullmatch(value)):
        return value
    raise _NotAllowedError


def number(value: Any, macs: MacAliases) -> Any:
    if isinstance(value, int | float) and not isinstance(value, bool):
        return value
    if value == "" or (isinstance(value, str) and _NUM.fullmatch(value)):
        return value
    raise _NotAllowedError


def flag(value: Any, macs: MacAliases) -> Any:
    if value in ("", "0", "1", 0, 1) and not isinstance(value, bool):
        return value
    raise _NotAllowedError


def private_ip(value: Any, macs: MacAliases) -> str:
    try:
        if isinstance(value, str) and ipaddress.IPv4Address(value).is_private:
            return value
    except ValueError:
        pass
    raise _NotAllowedError


def matching(pattern: re.Pattern[str]) -> Validator:
    def check(value: Any, macs: MacAliases) -> Any:
        if value == "" or (isinstance(value, str) and pattern.fullmatch(value)):
            return value
        raise _NotAllowedError

    return check


def diag_filter(value: Any, macs: MacAliases) -> str:
    match = _FILTER.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise _NotAllowedError
    return f"node_mac>txt>{macs.alias(match.group(1))}>0"


class Keys:
    """A dict schema: exact keys, plus regex-matched keys (optionally MAC keys)."""

    def __init__(
        self,
        exact: dict[str, Any] | None = None,
        *,
        pattern: re.Pattern[str] | None = None,
        value: Any = None,
        mac_keys: bool = False,
    ) -> None:
        self.exact = exact or {}
        self.pattern = pattern
        self.value = value
        self.mac_keys = mac_keys


class Items:
    """A list schema: every item follows ``schema``; bad items are dropped."""

    def __init__(self, schema: Any) -> None:
        self.schema = schema


def _scrub(value: Any, schema: Any, macs: MacAliases) -> Any:
    if isinstance(schema, Items):
        if not isinstance(value, list):
            raise _NotAllowedError
        kept = []
        for item in value:
            try:
                kept.append(_scrub(item, schema.schema, macs))
            except _NotAllowedError:
                continue
        return kept
    if isinstance(schema, Keys):
        if not isinstance(value, dict):
            raise _NotAllowedError
        kept_map: dict[str, Any] = {}
        for key, item in value.items():
            sub, name = schema.exact.get(key), key
            if sub is None and schema.mac_keys and normalize_mac(str(key)):
                sub, name = schema.value, macs.alias(str(key))
            elif sub is None and schema.pattern and schema.pattern.fullmatch(str(key)):
                sub = schema.value
            if sub is None:
                continue
            try:
                kept_map[name] = _scrub(item, sub, macs)
            except _NotAllowedError:
                continue
        return kept_map
    return schema(value, macs)


# --- schemas ----------------------------------------------------------------------

_MODEL_TEXT = matching(_MODEL)
_TRAFFIC = Keys(
    {
        "data": Keys(dict.fromkeys(("rx", "tx", "avg_rx", "avg_tx"), number)),
        "phy": Keys({"rx": number, "tx": number}),
        "error_status": integer,
    }
)
_NODE = Keys(
    {
        "mac": mac,
        "model_name": _MODEL_TEXT,
        "ui_model_name": _MODEL_TEXT,
        "product_id": _MODEL_TEXT,
        "fwver": _MODEL_TEXT,
        "ip": private_ip,
        "online": flag,
        "level": integer,
        "re_path": integer,
        "band_num": integer,
        "dwb_band": integer,
        "apdwb": mac,
        "papmlo": mac,
        "wired_mac": Items(mac),
        "band_info": Keys(
            pattern=re.compile(r"\d{1,2}"), value=Keys({"unit": integer})
        ),
        "config": Keys(
            {"wireless": Keys(pattern=re.compile(r"wl\d{1,2}_radio"), value=flag)}
        ),
        "wired_port": Keys(
            {
                "wan_port": Keys(
                    pattern=_PORT_LABEL,
                    value=Keys({"link_rate": matching(_LINK_RATE)}),
                )
            }
        ),
        **{
            f"ap{b}{s}": mac
            for b in ("2g", "5g", "5g1", "6g", "6g1")
            for s in ("", "_fh")
        },
        **{f"pap{b}": mac for b in ("2g", "5g", "6g")},
        **{f"rssi{b}": integer for b in ("2g", "5g", "6g")},
        **{f"sta{b}": mac for b in ("2g", "5g", "6g")},
    }
)
_CLIENT = Keys(
    {
        "mac": mac,
        "isOnline": flag,
        "isWL": integer,
        "rssi": integer,
        "curTx": number,
        "curRx": number,
        "amesh_papMac": mac,
        "amesh_isRe": flag,
        "mlo": flag,
        "isGN": integer,
        "sdn_type": matching(re.compile(r"[A-Z]{1,16}")),
        "mlo_links": Keys(
            pattern=re.compile(r"\dG\d?"),
            value=Keys(
                {
                    "mac": mac,
                    "rssi": integer,
                    "tx": number,
                    "rx": number,
                    "conn_time": matching(_DURATION),
                }
            ),
        ),
    }
)
APPGET = Keys(
    {
        "label_mac": mac,
        "lan_hwaddr": mac,
        "wan_hwaddr": mac,
        "productid": _MODEL_TEXT,
        "odmpid": _MODEL_TEXT,
        "firmver": _MODEL_TEXT,
        "buildno": _MODEL_TEXT,
        "extendno": _MODEL_TEXT,
        "swpjverno": _MODEL_TEXT,
        "wlnband_list": matching(_BANDS),
        "sw_mode": integer,
        "re_mode": integer,
        "wlc_psta": integer,
        "rc_support": matching(_FEATURES),
        "get_ui_support": Keys(pattern=_SAFE_KEY, value=integer),
        "uptime": matching(_UPTIME),
        "cpu_usage": Keys(
            pattern=re.compile(r"cpu\d{1,2}_(?:total|usage)"), value=integer
        ),
        "memory_usage": Keys(
            dict.fromkeys(
                ("mem_total", "mem_free", "mem_used", "simple_free", "simple_used"),
                integer,
            )
        ),
        "wl_control_channel": Items(integer),
        "get_clientlist": Keys(mac_keys=True, value=_CLIENT),
        "get_clientlist_from_json_database": Keys(
            mac_keys=True,
            value=Keys(
                {"mac": mac, "amesh_isRe": flag, "wireless": integer, "mlo": flag}
            ),
        ),
    },
    pattern=re.compile(r"wl\d{1,2}_(?:nband|radio)"),
    value=integer,
)
PAGES = {
    AREndpoint.FETCH_ONBOARDING.value: Keys(
        {
            "get_cfg_clientlist": Items(Items(_NODE)),
            "get_onboardingstatus": Items(
                Keys(
                    dict.fromkeys(
                        ("cfg_obstatus", "cfg_ready", "cfg_re_maxnum", "cfg_recount"),
                        integer,
                    )
                )
            ),
        }
    ),
    AREndpoint.FETCH_TEMPERATURE.value: Keys(
        {"curr_cpuTemp": matching(_NUM), "curr_coreTmp_cpu": matching(_NUM)},
        pattern=re.compile(r"curr_coreTmp_(?:wl)?\d{1,2}_raw"),
        value=matching(_TEMP),
    ),
}
QUERIES = {
    AREndpoint.FETCH_DIAGNOSTICS_DATA.value: (
        Keys({"filter": diag_filter}),
        Keys({"contents": Items(Items(integer))}),
    ),
    AREndpoint.FETCH_TRAFFIC_WIFI.value: (
        Keys({"node_mac": mac, "band_mac": mac}),
        _TRAFFIC,
    ),
    AREndpoint.FETCH_TRAFFIC_BACKHAUL.value: (
        Keys({"node_mac": mac, "sta_mac": mac}),
        _TRAFFIC,
    ),
    AREndpoint.FETCH_TRAFFIC_ETHERNET.value: (
        Keys({"node_mac": mac, "is_bh": flag}),
        _TRAFFIC,
    ),
}


def scrub(entries: list[Raw]) -> dict[str, Any]:
    """Build the fixture document the mock router replays (tests/fixtures)."""
    quiet_library_logging()  # the JSON reader would log bad replies verbatim
    macs = MacAliases()
    appget: dict[str, Any] = {}
    pages: dict[str, dict[str, Any]] = {}
    queries: dict[str, dict[str, Any]] = {}
    for entry in entries:
        try:
            text = entry.body.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if entry.endpoint == AREndpoint.FETCH_DATA.value:
            appget.update(_scrub(read_json_content(text), APPGET, macs))
        elif entry.endpoint in PAGES:
            variables = _scrub(read_js_variables(text), PAGES[entry.endpoint], macs)
            if entry.endpoint == AREndpoint.FETCH_ONBOARDING.value:
                variables["get_onboardinglist"] = [{}]  # candidates: foreign MACs
            pages.setdefault(entry.endpoint, {}).update(variables)
        elif entry.endpoint in QUERIES:
            query_schema, reply_schema = QUERIES[entry.endpoint]
            query = _scrub(entry.query, query_schema, macs)
            reply = _scrub(read_json_content(text), reply_schema, macs)
            key = json.dumps([entry.endpoint, query], sort_keys=True)
            queries.setdefault(
                key, {"endpoint": entry.endpoint, "query": query, "reply": reply}
            )
    return {
        "format": FIXTURE_FORMAT,
        "_source": "aimesh-snmp-proxy discover --fixtures; key-allowlist scrubbed",
        "appget": appget,
        "pages": pages,
        "queries": list(queries.values()),
    }
