"""Operator commands: ``run`` (the daemon), ``selftest``, and ``onboard``.

``__main__`` imports this package on demand and calls ``cli_<command>(config,
argv)``; each handler parses its own options and returns the exit code.
"""

from aimesh_snmp_proxy.ops.onboard import cli_onboard
from aimesh_snmp_proxy.ops.run import cli_run
from aimesh_snmp_proxy.ops.selftest import cli_selftest

__all__ = ["cli_onboard", "cli_run", "cli_selftest"]
