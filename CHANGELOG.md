# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

First public release. It continues the private 0.2.x line.

### Added

- SNMP proxy for ASUS routers on stock firmware. It serves one SNMP v2c or v3 engine on `127.0.0.1`
  for each AiMesh root, AiMesh node, standalone router, access point, or media bridge.
- Served data: system info, uptime, CPU per core, memory, temperatures, radios and Ethernet ports
  with octet counters, clients per band, LLDP links for the wireless backhaul, and Rx-power sensors.
- A device with an empty AiMesh list is served as one root, so router, access point, and media
  bridge modes work without AiMesh nodes.
- `per_node` collector mode. It adds uptime, temperatures, CPU cores, RAM, and exact traffic
  counters for each node, with node certificate pins (`--pin-node-ca` and `[[override]] ca_file`).
- Commands `check-config`, `discover`, `selftest`, `onboard`, `dump-snmprec`, and `init`.
- `init` and `scripts/generate-config.sh` write a validated `config.toml` and secret files for any
  ASUS router type. `--detect` pins the router certificate and tells an AiMesh root from a
  standalone device with one login.
- `onboard` adds the devices to LibreNMS through its API. It runs as a dry run by default and
  deletes only the devices it created.
- `deploy/install.sh` for systemd hosts. It installs hash-pinned binary wheels, runs the service as a
  `DynamicUser`, adds service instances for more routers, upgrades in place, and uninstalls.
- Documentation site with an onboarding guide for each router type, a configuration reference,
  operations, troubleshooting, and a security model.

### Security

- The router link uses HTTPS only, with pinned certificates, a read-only request allowlist, and a
  login budget of 6 logins per hour for each device.
- Secrets live in root-only files and reach the service as systemd credentials. A log filter masks
  secrets and the device half of MAC addresses.
- Each release ships the offline bundle, a wheel, an sdist, and `SHA256SUMS`. Every file carries a
  build attestation that `gh attestation verify` checks.
