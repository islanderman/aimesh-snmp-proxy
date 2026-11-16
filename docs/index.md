# aimesh-snmp-proxy

Monitor ASUS routers in LibreNMS over SNMP. No agent runs on the router.

aimesh-snmp-proxy is a service for the Linux host that runs LibreNMS. It logs in to an ASUS router
with stock firmware over HTTPS, reads its status, and answers SNMP on `127.0.0.1`. LibreNMS polls it
like any other SNMP device. Each AiMesh node, standalone router, access point, or media bridge shows
up as its own device with wireless sensors.

## What LibreNMS shows

- System information: model, firmware, name, location, and uptime.
- CPU load per core, memory, and temperatures.
- Radios as ports, with 64-bit octet counters.
- Ethernet ports with link state and speed (WAN and LAN rows).
- Wi-Fi clients per band, channel frequency, and signal level.
- LLDP links for the wireless backhaul between nodes.

See [LibreNMS](librenms.md) for the details and for what stock firmware does not report.

## Supported devices

| Your device                   | LibreNMS shows                          | Guide                                          |
| ----------------------------- | --------------------------------------- | ---------------------------------------------- |
| AiMesh root router with nodes | The root and each node, one device each | [AiMesh root with nodes](onboarding/aimesh.md) |
| Standalone router             | One device                              | [Standalone router](onboarding/router.md)      |
| Access point (AP mode)        | One device                              | [Access point](onboarding/access-point.md)     |
| Media bridge                  | One device, with 0 Wi-Fi clients        | [Media bridge](onboarding/media-bridge.md)     |

All of them must run stock ASUS firmware with HTTPS admin login. You can serve many routers from one
host. See [Multiple routers](instances.md).

## How it works

```text
ASUS root router -- HTTPS, pinned certificate ------>  aimesh-snmp-proxy  -- SNMP, 127.0.0.1 -->  LibreNMS
AiMesh nodes ------ HTTPS, per_node mode only ------>  one SNMP port per device
```

1. The proxy logs in to the router and reads status pages. It never changes a setting.
2. It builds one snapshot for each device.
3. It runs one SNMP engine for each device, on its own port on `127.0.0.1`.
4. LibreNMS polls each port. The proxy imitates the LibreNMS OS `asuswrt-merlin`, so LibreNMS
   creates its wireless sensors on its own.

The proxy never serves old data. A device that stops reporting stops answering, and LibreNMS marks
it down.

## Requirements

- A Linux host with systemd and Python 3.11 or newer. LibreNMS runs on the same host.
- A router with stock ASUS firmware and HTTPS admin login.
- LibreNMS 26.x, to add the devices with `onboard`.

The full list is in [Installation](installation.md#requirements).

## Start here

1. [Install the service](installation.md).
2. [Pick your router type](onboarding/index.md) and follow its guide.
3. [Add the devices to LibreNMS](librenms.md).

Then read [Operations](operations.md) and the [security model](security.md). If something fails, see
[Troubleshooting](troubleshooting.md).

## About the project

aimesh-snmp-proxy is open source under the Apache License 2.0. The source is on
[GitHub](https://github.com/islanderman/aimesh-snmp-proxy). The project is independent. ASUS and
AiMesh are trademarks of ASUSTeK Computer Inc. LibreNMS is a trademark of its owners.
