"""Poll a stock-firmware ASUS router and serve each node over SNMP for LibreNMS.

An AiMesh root serves itself and every node; a standalone router, access point
or media bridge (an empty AiMesh list) is served as one root node.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("aimesh-snmp-proxy")
except PackageNotFoundError:  # pragma: no cover - source tree without install
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
