import pytest
from pysnmp.proto import rfc1902, rfc1905
from pysnmp.smi import error as smi_error

from aimesh_snmp_proxy.snmp.instrum import TableController
from aimesh_snmp_proxy.snmp.oidtable import OidTable

SYS_DESCR = (1, 3, 6, 1, 2, 1, 1, 1, 0)
SYS_NAME = (1, 3, 6, 1, 2, 1, 1, 5, 0)
IF_NUMBER = (1, 3, 6, 1, 2, 1, 2, 1, 0)
MISSING = (1, 3, 6, 1, 2, 1, 1, 7, 0)

TABLE = OidTable(
    [
        (SYS_DESCR, rfc1902.OctetString(b"descr")),
        (SYS_NAME, rfc1902.OctetString(b"node")),
        (IF_NUMBER, rfc1902.Integer32(3)),
    ]
)


class Access:
    """Records acFun calls; denies OIDs in ``hidden``, raises for ``forbidden``."""

    def __init__(self, hidden=(), forbidden=()):
        self.hidden = set(hidden)
        self.forbidden = set(forbidden)
        self.calls = []

    def __call__(self, view_type, var_bind, **context):
        name, value = var_bind
        self.calls.append((view_type, tuple(name), value, context.get("idx")))
        if tuple(name) in self.forbidden:
            raise smi_error.AuthorizationError(name=name, idx=context.get("idx"))
        return tuple(name) in self.hidden


def request(*oids):
    return [(rfc1902.ObjectName(oid), rfc1905.unSpecified) for oid in oids]


def names(var_binds):
    return [tuple(name) for name, _ in var_binds]


def test_starts_with_an_empty_table():
    rsp = TableController().read_variables(*request(SYS_NAME))
    assert rsp[0][1] is rfc1905.noSuchObject


def test_get_returns_values_in_request_order():
    rsp = TableController(TABLE).read_variables(*request(SYS_NAME, SYS_DESCR))
    assert names(rsp) == [SYS_NAME, SYS_DESCR]
    assert [bytes(value) for _, value in rsp] == [b"node", b"descr"]


def test_get_of_a_missing_oid_is_no_such_object():
    rsp = TableController(TABLE).read_variables(*request(MISSING, SYS_NAME[:-1]))
    assert [value for _, value in rsp] == [rfc1905.noSuchObject] * 2


def test_get_outside_the_view_is_no_such_object():
    access = Access(hidden={SYS_NAME})
    rsp = TableController(TABLE).read_variables(
        *request(SYS_NAME, SYS_DESCR), acFun=access
    )
    assert rsp[0][1] is rfc1905.noSuchObject
    assert bytes(rsp[1][1]) == b"descr"


def test_get_checks_access_for_every_varbind_even_missing_ones():
    access = Access()
    TableController(TABLE).read_variables(
        *request(MISSING, SYS_NAME), acFun=access, snmpEngine="engine"
    )
    assert [(oid, idx) for _, oid, _, idx in access.calls] == [
        (MISSING, 0),
        (SYS_NAME, 1),
    ]
    assert {view for view, *_ in access.calls} == {"read"}


def test_access_check_sees_the_request_context():
    seen = {}

    def ac_fun(view_type, var_bind, **context):
        seen.update(context)
        return False

    TableController(TABLE).read_variables(
        *request(SYS_NAME), acFun=ac_fun, snmpEngine="engine", cbCtx=None
    )
    assert seen["snmpEngine"] == "engine"
    assert seen["idx"] == 0


def test_authorization_error_aborts_the_request():
    access = Access(forbidden={MISSING})
    with pytest.raises(smi_error.AuthorizationError):
        TableController(TABLE).read_variables(*request(MISSING), acFun=access)


def test_get_next_returns_the_following_rows():
    rsp = TableController(TABLE).read_next_variables(
        *request((1, 3, 6), SYS_DESCR, (1, 3, 6, 1, 2, 1, 1, 9))
    )
    assert names(rsp) == [SYS_DESCR, SYS_NAME, IF_NUMBER]
    assert int(rsp[2][1]) == 3


def test_get_next_past_the_end_is_end_of_mib_view():
    rsp = TableController(TABLE).read_next_variables(*request(IF_NUMBER))
    assert names(rsp) == [IF_NUMBER]
    assert rsp[0][1] is rfc1905.endOfMibView


def test_get_next_skips_rows_outside_the_view():
    access = Access(hidden={SYS_DESCR, SYS_NAME})
    rsp = TableController(TABLE).read_next_variables(*request((1, 3)), acFun=access)
    assert names(rsp) == [IF_NUMBER]
    assert [oid for _, oid, _, _ in access.calls] == [SYS_DESCR, SYS_NAME, IF_NUMBER]


def test_get_next_with_every_row_hidden_is_end_of_mib_view():
    access = Access(hidden={SYS_DESCR, SYS_NAME, IF_NUMBER})
    rsp = TableController(TABLE).read_next_variables(*request((1, 3)), acFun=access)
    assert rsp[0][1] is rfc1905.endOfMibView


def test_get_next_authorization_error_propagates():
    access = Access(forbidden={SYS_DESCR})
    with pytest.raises(smi_error.AuthorizationError):
        TableController(TABLE).read_next_variables(*request((1, 3)), acFun=access)


def test_a_swapped_table_serves_the_next_request():
    controller = TableController(TABLE)
    controller.table = OidTable([(SYS_NAME, rfc1902.OctetString(b"renamed"))])
    rsp = controller.read_variables(*request(SYS_NAME, SYS_DESCR))
    assert bytes(rsp[0][1]) == b"renamed"
    assert rsp[1][1] is rfc1905.noSuchObject


def test_writes_are_refused():
    with pytest.raises(smi_error.SmiError):
        TableController(TABLE).write_variables(
            (rfc1902.ObjectName(SYS_NAME), rfc1902.OctetString(b"x"))
        )
