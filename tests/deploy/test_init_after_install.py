"""``init`` after the real install.sh: its untouched seed needs no ``--force``."""

import io
import secrets
from pathlib import Path

import pytest

from aimesh_snmp_proxy.config import load_config
from aimesh_snmp_proxy.ops import configure


def run_init(argv):
    out, err = io.StringIO(), io.StringIO()
    password = io.StringIO(f"pw-{secrets.token_hex(8)}\n")  # built at run time
    code = configure.cli_init(None, argv, out=out, err=err, stdin=password)
    return code, out.getvalue(), err.getvalue()


@pytest.mark.parametrize("instance", [None, "lab"])
def test_init_replaces_what_install_sh_seeded(host, instance):
    args = ("--instance", instance) if instance else ()
    installed = host.run(*args)
    assert installed.returncode == 0, installed.stderr
    folder = host.instance_etc(instance) if instance else host.etc
    argv = ["--host", "192.168.50.1", "--password-stdin", "--output-dir", str(folder)]
    code, out, err = run_init([*argv, *args])
    assert code == 0, err
    assert "replaced install.sh's placeholders: asus_password," in out
    cfg = load_config(folder / "config.toml", env={})
    suffix = f"-{instance}" if instance else ""
    assert cfg.state_dir == Path(f"/var/lib/aimesh-snmp-proxy{suffix}")
    again, _, err = run_init([*argv, *args])
    assert again == 1  # now it holds a real config: --force is needed
    assert "--force" in err
