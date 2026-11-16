# Installation and verification

The proxy runs as a systemd service on the same host as the LibreNMS poller. It listens on
`127.0.0.1` only, so LibreNMS must poll from that host.

This page installs the service. The [onboarding guides](onboarding/index.md) then configure it for
your router type.

## Requirements

### Host

- Linux with systemd. Version 247 or newer is the normal path (`DynamicUser=` and
  `LoadCredential=`). An older systemd works for one service only. The installer then uses a static
  `aimesh-snmp-proxy` user. Instances need 247 or newer.
- Python 3.11 or newer with the `venv` module. On Debian and Ubuntu, run
  `sudo apt install python3-venv`. If Python has no `venv`, the installer builds the environment
  with `uv` when `uv` is on the path.
- Python must live outside `/home`, `/root`, and `/run/user`. The service cannot see those folders.
- Root access through `sudo`.
- Access to PyPI during the install. The installer downloads hash-pinned binary wheels.
- A route from the host to the router over HTTPS. The default port is 8443.

### Router

- Stock ASUS firmware.
- HTTPS admin login. Open _Administration_, then _System_, and set _Authentication Method_ to
  `HTTPS` or `Both`. The HTTPS port is 8443 by default.
- A fixed address. Give the router and every AiMesh node a DHCP reservation.
- The admin user name and password.

### LibreNMS

- LibreNMS 26.x, installed natively on the same host. A container is untested: the proxy listens on
  the loopback address of its own host only.
- An administrator who can create an API token. Only `onboard` uses the token.

## Download and verify the release

Download the bundle and its checksum file from the
[releases page](https://github.com/islanderman/aimesh-snmp-proxy/releases).

A release holds five files. You need the bundle and `SHA256SUMS`.

| File                                       | Use                                                    |
| ------------------------------------------ | ------------------------------------------------------ |
| `aimesh-snmp-proxy-X.Y.Z.tar.gz`           | The offline bundle that `deploy/install.sh` installs   |
| `aimesh-snmp-proxy-X.Y.Z.tar.gz.sha256`    | The checksum of the bundle                             |
| `aimesh_snmp_proxy-X.Y.Z-py3-none-any.whl` | The Python wheel                                       |
| `aimesh_snmp_proxy-X.Y.Z.tar.gz`           | The source distribution                                |
| `SHA256SUMS`                               | The checksums of the wheel, the source, and the bundle |

Use a scratch folder for the download.

```sh
VERSION=0.3.0
BASE=https://github.com/islanderman/aimesh-snmp-proxy/releases/download/v$VERSION
mkdir -p ~/aimesh-download && cd ~/aimesh-download
curl -fsSLO "$BASE/aimesh-snmp-proxy-$VERSION.tar.gz"
curl -fsSLO "$BASE/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS
```

The last command prints `aimesh-snmp-proxy-0.3.0.tar.gz: OK`. Stop if it prints anything else.

The release workflow also attests every file. If you have the GitHub CLI, you can check that the
bundle came from this repository's release workflow:

```sh
gh attestation verify aimesh-snmp-proxy-$VERSION.tar.gz --repo islanderman/aimesh-snmp-proxy
```

The bundle also holds its own `SHA256SUMS` for every file inside it. The installer checks that list
before it changes anything.

## Install

Unpack the bundle as root, then run the installer. Start with a dry run. A dry run needs no root. It
runs every check and prints the plan. It changes nothing. Stop every running service first: the
installer refuses to run while one runs, in a dry run too.

```sh
sudo tar -xzf aimesh-snmp-proxy-$VERSION.tar.gz -C /usr/local/src
cd /usr/local/src/aimesh-snmp-proxy-$VERSION
sudo ./deploy/install.sh --dry-run
sudo ./deploy/install.sh
```

If the dry run reports an error, fix it and run it again. The installer exits before it changes
anything when a check fails. Common errors:

| Message                                    | Fix                                                        |
| ------------------------------------------ | ---------------------------------------------------------- |
| `no Python >= 3.11 found`                  | Install Python 3.11 or newer, or pass `--python /path`     |
| `python lacks venv or ensurepip`           | `sudo apt install python3-venv`, or install `uv`           |
| `is active: stop it first`                 | `sudo systemctl stop aimesh-snmp-proxy`, then run again    |
| `under a directory the service cannot see` | Use a system-wide Python, not one under `/home` or `/root` |
| `bundle checksum mismatch`                 | Download the bundle again                                  |

The installer never starts or enables the service. It never reads a secret file and never prints a
secret. It does this:

1. Checks root, the bundle checksums, Python, systemd, that no service runs, and `config.toml`.
2. Builds a virtual environment in `/opt/aimesh-snmp-proxy/venv`. It installs only hash-pinned
   binary wheels, with no dependency resolution. The old environment waits aside until the new one
   imports. If the build fails, the installer restores the old one.
3. Creates `/etc/aimesh-snmp-proxy` (mode 0700). It copies `config.example.toml` to `config.toml`
   when no `config.toml` exists. It creates the empty files `asus_password`, `snmp_community`, and
   `asus_router.pem` (mode 0600). It keeps any file that exists.
4. Writes `/etc/systemd/system/aimesh-snmp-proxy.service`. It fills in the install path and the
   address allow list from `asus.host`. In `per_node` mode, the list also holds `nodes.expected`.
5. Runs `systemctl daemon-reload` and `systemd-analyze verify` when available.

After it finishes, the layout is:

```text
/opt/aimesh-snmp-proxy/venv/                  Python environment
/etc/aimesh-snmp-proxy/config.toml            your configuration
/etc/aimesh-snmp-proxy/asus_password          router password (you fill it in)
/etc/aimesh-snmp-proxy/snmp_community         SNMP community (you fill it in)
/etc/aimesh-snmp-proxy/asus_router.pem        pinned router certificate (you create it)
/etc/systemd/system/aimesh-snmp-proxy.service the unit
/var/lib/aimesh-snmp-proxy/                   state, created at the first run of the service
```

Next, write the config. Follow the guide for your router type: [Choose your path](onboarding/index.md).
Its first step runs `init`, which asks a few questions and writes the config and the secrets.

## Check the sandbox

Run these after the first start. They show how well systemd confines the service.

```sh
systemd-analyze verify /etc/systemd/system/aimesh-snmp-proxy.service
systemd-analyze security aimesh-snmp-proxy
```

## Installer options

| Option            | Meaning                                                                       |
| ----------------- | ----------------------------------------------------------------------------- |
| `--dry-run`       | Run every check, print the plan, change nothing. No root needed               |
| `--python PATH`   | Use this Python. The default search is 3.12, 3.11, 3.13, 3.14, then `python3` |
| `--prefix DIR`    | Install the environment under `DIR`. The default is `/opt/aimesh-snmp-proxy`  |
| `--instance NAME` | Add one more service for another router. See [Multiple routers](instances.md) |
| `--uninstall`     | Stop the service, remove the unit and the environment, keep config and state  |
| `--purge`         | With `--uninstall`, also delete the config and the state                      |
| `--yes`           | With `--purge`, skip the confirmation                                         |
| `-h`, `--help`    | Print the usage text                                                          |

The environment variable `DESTDIR` installs below that folder. It is for tests and packaging.

Running the installer again upgrades in place. See [Operations](operations.md).

## Build the bundle from source

The release workflow builds the bundle for you. To build your own, you need `git`, `uv`, and network
access.

```sh
git clone https://github.com/islanderman/aimesh-snmp-proxy.git
cd aimesh-snmp-proxy
git checkout v0.3.0
make bundle
```

`make bundle` runs `deploy/build-bundle.sh`. It packs the committed `HEAD`: your own wheel, a wheel
of each git-pinned dependency, and a hash-pinned `requirements.txt` exported from `uv.lock`. The
result is `dist/aimesh-snmp-proxy-VERSION.tar.gz` and a `.sha256` file. The archive is reproducible:
its entries are root-owned and carry the commit time.
