# aimesh-snmp-proxy

[![CI](https://github.com/islanderman/aimesh-snmp-proxy/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/islanderman/aimesh-snmp-proxy/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/islanderman/aimesh-snmp-proxy)](https://github.com/islanderman/aimesh-snmp-proxy/releases/latest)
[![License](https://img.shields.io/github/license/islanderman/aimesh-snmp-proxy)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](https://github.com/islanderman/aimesh-snmp-proxy/blob/main/pyproject.toml)
[![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://islanderman.github.io/aimesh-snmp-proxy/)

Monitor ASUS routers in LibreNMS over SNMP. It works with AiMesh roots and nodes, standalone
routers, access points, and media bridges that run stock ASUS firmware.

aimesh-snmp-proxy is a systemd service for the host that runs LibreNMS. It logs in to the router
over HTTPS, reads its status, and answers SNMP on `127.0.0.1`. LibreNMS polls it like any other
SNMP device. Each router, AiMesh node, access point, or media bridge shows up as its own wireless
device. The proxy only reads: it never changes a router setting.

## Supported devices

| Your device                   | LibreNMS shows                          | Guide                                                                                        |
| ----------------------------- | --------------------------------------- | -------------------------------------------------------------------------------------------- |
| AiMesh root router with nodes | The root and each node, one device each | [AiMesh root with nodes](https://islanderman.github.io/aimesh-snmp-proxy/onboarding/aimesh/) |
| Standalone router             | One device                              | [Standalone router](https://islanderman.github.io/aimesh-snmp-proxy/onboarding/router/)      |
| Access point (AP mode)        | One device                              | [Access point](https://islanderman.github.io/aimesh-snmp-proxy/onboarding/access-point/)     |
| Media bridge                  | One device, with 0 Wi-Fi clients        | [Media bridge](https://islanderman.github.io/aimesh-snmp-proxy/onboarding/media-bridge/)     |

A media bridge serves no Wi-Fi clients, so 0 clients is correct. A device with an empty AiMesh list
is served as one root device. You can serve many routers from one host.

## What LibreNMS shows

- System information: model, firmware, name, location, and uptime.
- CPU load per core, memory, and temperatures.
- Radios as ports with 64-bit octet counters, and Ethernet ports (WAN and LAN) with link state and
  speed.
- Wi-Fi clients per band, channel frequency, and signal level.
- LLDP links for the wireless backhaul between nodes.

Stock firmware reports no traffic per Ethernet port. A port gets counters only when a traffic total
covers that port alone. Ports that share a total show their link state and no traffic.

## Quick start

You need a Linux host with systemd and Python 3.11 or newer, LibreNMS 26.x on the same host, and a
router with stock ASUS firmware. In the router web UI, set _Administration_,
_System_, _Authentication Method_ to `HTTPS` or `Both`.

**1. Download and verify the release.**

```sh
VERSION=0.3.0
BASE=https://github.com/islanderman/aimesh-snmp-proxy/releases/download/v$VERSION
curl -fsSLO "$BASE/aimesh-snmp-proxy-$VERSION.tar.gz"
curl -fsSLO "$BASE/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS
```

**2. Install.** The installer never starts the service.

```sh
sudo tar -xzf aimesh-snmp-proxy-$VERSION.tar.gz -C /usr/local/src
cd /usr/local/src/aimesh-snmp-proxy-$VERSION
sudo ./deploy/install.sh --dry-run
sudo ./deploy/install.sh
```

**3. Generate the config.** `init` asks for the router address and the admin password. It pins the
router certificate after you compare the fingerprint, detects AiMesh nodes, and writes the config
and the secrets. It replaces the files that the installer seeded, and your own edits only with
`--force`. Run the installer again so the unit can reach the router.

```sh
APP=/opt/aimesh-snmp-proxy/venv/bin/aimesh-snmp-proxy
sudo $APP init --detect
sudo ./deploy/install.sh
```

**4. Check, then start.**

```sh
sudo $APP discover
sudo $APP check-config
sudo $APP selftest
sudo systemctl enable --now aimesh-snmp-proxy
```

**5. Add the devices to LibreNMS.** Create an API token, add an `[onboard]` table to the config, and
wait 6 minutes after the start. Then:

```sh
sudo -u librenms /opt/librenms/lnms config:set icmp_check false
sudo $APP onboard
sudo $APP onboard --apply
sudo -u librenms /opt/librenms/lnms config:set icmp_check true
```

The [onboarding guide](https://islanderman.github.io/aimesh-snmp-proxy/onboarding/) walks through
each step for your router type.

## Documentation

- [Choose your path](https://islanderman.github.io/aimesh-snmp-proxy/onboarding/): step by step for
  each router type.
- [Installation](https://islanderman.github.io/aimesh-snmp-proxy/installation/): requirements,
  download, verification, installer options.
- [Reference](https://islanderman.github.io/aimesh-snmp-proxy/reference/configuration/):
  configuration keys, the command line, and the served metrics.
- [Multiple routers](https://islanderman.github.io/aimesh-snmp-proxy/instances/): one service for
  each router.
- [LibreNMS](https://islanderman.github.io/aimesh-snmp-proxy/librenms/): what you see, and how
  `onboard` works.
- [Operations](https://islanderman.github.io/aimesh-snmp-proxy/operations/): upgrade, roll back,
  rotate secrets, uninstall.
- [Troubleshooting](https://islanderman.github.io/aimesh-snmp-proxy/troubleshooting/) and
  [FAQ](https://islanderman.github.io/aimesh-snmp-proxy/faq/).

## Security

- The service runs as a throwaway `DynamicUser` in a systemd sandbox. It is never root.
- Secrets live in root-only files and reach the service as systemd credentials. They never travel in
  environment variables or on command lines.
- The router link is HTTPS only, with pinned certificates. A request allowlist permits read pages
  only. A login budget protects the router.
- SNMP listens on `127.0.0.1` only and never answers with old data.
- Installs use hash-pinned binary wheels and a checksummed bundle.

Read the full [security model](https://islanderman.github.io/aimesh-snmp-proxy/security/). Report a
vulnerability as the [security policy](SECURITY.md) describes.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Release notes are in the [changelog](CHANGELOG.md).

## License

Apache License 2.0. See [LICENSE](LICENSE). Copyright 2026 Jerry Yang.

This project is independent. ASUS, AiMesh, and ASUSWRT are trademarks of ASUSTeK Computer Inc.
LibreNMS is a trademark of its owners.
