# Served metrics

The proxy serves each device as its own SNMP device. This page lists what a device serves, where the
values come from, and what LibreNMS shows. See
[Differences by router type](#differences-by-router-type) for what changes between an AiMesh root, an
AiMesh node, a standalone router, an access point, and a media bridge.

## How a device is served

- Each device has one SNMP engine on its own UDP port on `127.0.0.1`. See
  [SNMP ports](configuration.md#snmp-ports).
- The engine answers SNMP v2c with the community from `snmp.community_file`, SNMPv3 authPriv with the
  user from `[snmp.v3]`, or both.
- The engine is read-only. It answers GET, GETNEXT, and GETBULK. It has no SET.
- The view covers the subtree `1.3.6` and the LLDP-MIB subtree `1.0.8802.1.1.2`.
- Unknown data omits its OID. The proxy never invents a value. The only stand-ins are the standard
  "unknown" codes: `ifSpeed` 0 and `ifOperStatus` unknown(4).
- The proxy serves no UCD-SNMP-MIB, no packet, error, or discard counters, and no SNR or noise floor.

LibreNMS picks the `asuswrt-merlin` OS from two OIDs:

| OID                             | Value                               | Use                                               |
| ------------------------------- | ----------------------------------- | ------------------------------------------------- |
| `1.3.6.1.2.1.1.2.0`             | `1.3.6.1.4.1.8072.3.2.10`           | sysObjectID: the net-snmp Linux identifier        |
| `1.3.6.1.4.1.2021.7890.1.101.1` | `ASUSWRT-Merlin <model> <firmware>` | OS detection, hardware name, and firmware version |

The model and the firmware are one word each: a space turns into `_`.

### When a device is silent

A device answers only while it has fresh data. Otherwise the engine drops the packet without a
reply, and LibreNMS sees an SNMP timeout. A device is silent when:

- it is absent from the latest AiMesh list,
- the root reported it offline in two polls in a row,
- the proxy has no data for it yet, or
- its newest data is older than `collector.stale_after_s`.

The proxy never serves old data as if it were new.

### Check a device

```sh
snmpget -v2c -c COMMUNITY -Oq 127.0.0.1:16102 1.3.6.1.2.1.1.5.0 1.3.6.1.2.1.1.1.0
```

```text
SNMPv2-MIB::sysName.0 aimesh-005312
SNMPv2-MIB::sysDescr.0 ASUS RT-AX88U stock 3.0.0.4.388_00000 via aimesh-snmp-proxy
```

Use `aimesh-snmp-proxy selftest` to check every device. Use `dump-snmprec` to see the OIDs for a
snapshot. See [Command line](cli.md).

## System and uptime

| OID                    | Object         | Value                                                                            |
| ---------------------- | -------------- | -------------------------------------------------------------------------------- |
| `1.3.6.1.2.1.1.1.0`    | sysDescr       | `ASUS <model> stock <firmware> via aimesh-snmp-proxy`; an unknown part drops out |
| `1.3.6.1.2.1.1.2.0`    | sysObjectID    | `1.3.6.1.4.1.8072.3.2.10`                                                        |
| `1.3.6.1.2.1.1.3.0`    | sysUpTime      | Uptime in hundredths of a second                                                 |
| `1.3.6.1.2.1.1.4.0`    | sysContact     | Empty                                                                            |
| `1.3.6.1.2.1.1.5.0`    | sysName        | `aimesh-root`, `aimesh-<last 6 hex digits of the MAC>`, or the override name     |
| `1.3.6.1.2.1.1.6.0`    | sysLocation    | The `location` of the override, else empty                                       |
| `1.3.6.1.2.1.25.1.1.0` | hrSystemUptime | The same ticks as sysUpTime. Served only when the device uptime is known         |

Uptime comes from one of two sources:

- When the device reports its uptime, the proxy serves that value, advanced by the time since the
  poll. It reads the uptime from the device that it logs in to: the root, a standalone device, or a
  node in `per_node` mode. Some firmware versions report none.
- Otherwise `sysUpTime` counts from the moment the proxy started to serve the device, and
  `hrSystemUptime` is absent.

The proxy drops the device detail that it cannot refresh for 10 minutes: uptime, CPU cores, RAM size,
temperatures, and channels. `sysUpTime` then counts from the start of serving until the next poll
succeeds. Keep `collector.topology_interval_s` at 540 or less, or the detail lapses between two
polls.

## CPU and memory

| OID                              | Object          | Value                                                                                                          |
| -------------------------------- | --------------- | -------------------------------------------------------------------------------------------------------------- |
| `1.3.6.1.2.1.25.3.2.1.{1,2,3}.N` | hrDeviceTable   | One processor row for each core. `N` is 196608 + core number. `hrDeviceDescr` is `Core 0`, `Core 1`, and so on |
| `1.3.6.1.2.1.25.3.3.1.2.N`       | hrProcessorLoad | Load in percent, rounded and held between 0 and 100                                                            |
| `1.3.6.1.2.1.25.2.2.0`           | hrMemorySize    | RAM size in KiB. Served only when the device detail is known                                                   |
| `1.3.6.1.2.1.25.2.3.1.{1..6}.1`  | hrStorageTable  | One row, index 1: type RAM, the descr, the unit, the size, and the used amount                                 |

- A device that reports its CPU cores serves one row for each core. Core load needs two samples of
  the device detail, so it appears from the second detail poll on (`collector.topology_interval_s`
  apart). After a restart, the cores of the root appear about one interval after the first poll.
  The cores of a `per_node` node appear up to two intervals after the start, because the first
  detail poll of each node comes at its own time within the first interval.
- Without core data, the device serves one row, `CPU`, with the total percent that the router
  reports.
- With the RAM size and the used bytes, the storage row is `Physical memory`: unit 1024 bytes, size and
  used in KiB.
- Without them, the storage row is `Physical memory (%)`: unit 1, size 100, used equal to the
  percent that the router reports.

## Temperatures

The proxy serves each temperature sensor as an ENTITY-SENSOR-MIB row of type celsius.

| OID                          | Object                 | Value                                          |
| ---------------------------- | ---------------------- | ---------------------------------------------- |
| `1.3.6.1.2.1.47.1.1.1.1.2.N` | entPhysicalDescr       | `CPU temperature`, `wl-5.0G radio temperature` |
| `1.3.6.1.2.1.47.1.1.1.1.7.N` | entPhysicalName        | `CPU`, `wl-5.0G radio`                         |
| `1.3.6.1.2.1.99.1.1.1.1.N`   | entPhySensorType       | `8` (celsius)                                  |
| `1.3.6.1.2.1.99.1.1.1.2.N`   | entPhySensorScale      | `9` (units)                                    |
| `1.3.6.1.2.1.99.1.1.1.3.N`   | entPhySensorPrecision  | `1`                                            |
| `1.3.6.1.2.1.99.1.1.1.4.N`   | entPhySensorValue      | The temperature times 10: `610` is 61.0 °C     |
| `1.3.6.1.2.1.99.1.1.1.5.N`   | entPhySensorOperStatus | `1` (ok)                                       |

- `N` counts from 1, in the alphabetical order of the router's sensor keys: `cpu`, then
  `radio_2g1`, `radio_5g1`, and so on.
- The device reports temperatures in its detail. A node serves them only in `per_node` mode. A
  device that reports none serves none.

## Rx-power sensors

The proxy serves two kinds of signal sensors. LibreNMS does not take the dBm type of
ENTITY-SENSOR-MIB. It does take type `other` (1) when `entPhysicalName` ends in `Rx Power Sensor`,
and shows it as a dBm sensor. The proxy uses that path.

| Sensor               | `N`          | `entPhysicalName`                 | Precision | Value                                     |
| -------------------- | ------------ | --------------------------------- | --------- | ----------------------------------------- |
| Backhaul signal      | `100`        | `backhaul Rx Power Sensor`        | 0         | The backhaul RSSI in dBm                  |
| Client signal, radio | `200` + unit | `wl-5.0G clients Rx Power Sensor` | 1         | The average RSSI of the clients, times 10 |

- The backhaul sensor exists for a node with a wireless backhaul that reports its signal.
- A client sensor exists for each radio that has at least one client with a signal value.
- `entPhysicalDescr` reads `backhaul RSSI in dBm` and `wl-5.0G client RSSI average in dBm`. The other
  object OIDs are the same as for temperatures.
- The precision is fixed for each sensor, because LibreNMS reads it once at discovery.

The radio label comes from the band: `2g1` is `wl-2.4G`, `2g2` is `wl-2.4G-2`, `5g1` is `wl-5.0G`,
`5g2` is `wl-5.0G-2`, `6g1` is `wl-6.0G`, and `6g2` is `wl-6.0G-2`. Another band uses `wl<unit>`.

## Interfaces

The `ifTable` and `ifXTable` of IF-MIB list the radios, the wired links, and the Ethernet ports of
the device.

### Interface rows

| `ifIndex` | `ifName`   | Row                                                                                   |
| --------- | ---------- | ------------------------------------------------------------------------------------- |
| `1`       | `wired`    | The wired total of the device. Exists when a traffic source reports it                |
| `2`       | `backhaul` | The uplink of a node to its AiMesh parent                                             |
| `10`      | `wl0`      | Radio 0 (`10` + the unit): `wl1` is `11`, `wl2` is `12`                               |
| `100`     | `WAN`      | The first WAN port. `WAN2` is `101`, and so on                                        |
| `111`     | `LAN1`     | The first LAN port (`110` + the port number). `LAN2` is `112`, up to `LAN99` at `209` |

- The wired and backhaul rows exist only when the proxy has data for them.
- The Ethernet rows (`WAN`, `LAN<n>`) exist when the router reports its port status.
- The index of a port does not change when other ports come and go.

### Columns

| OID                         | Object        | Value                                                                                                                              |
| --------------------------- | ------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `1.3.6.1.2.1.2.1.0`         | ifNumber      | The number of rows                                                                                                                 |
| `1.3.6.1.2.1.2.2.1.1.N`     | ifIndex       | The index                                                                                                                          |
| `1.3.6.1.2.1.2.2.1.2.N`     | ifDescr       | The same as `ifName`                                                                                                               |
| `1.3.6.1.2.1.2.2.1.3.N`     | ifType        | `6` for wired and Ethernet, `71` for a radio. For the backhaul: `71` (wireless), `6` (wired), or `1` (medium unknown)              |
| `1.3.6.1.2.1.2.2.1.5.N`     | ifSpeed       | Speed in bit/s, at most 4294967295. `0` when unknown                                                                               |
| `1.3.6.1.2.1.2.2.1.6.N`     | ifPhysAddress | The device MAC on `wired`, the radio MAC on a radio. The other rows have none                                                      |
| `1.3.6.1.2.1.2.2.1.7.N`     | ifAdminStatus | `1` (up). For a radio: `1` when the radio is on, else `2`                                                                          |
| `1.3.6.1.2.1.2.2.1.8.N`     | ifOperStatus  | See the table below                                                                                                                |
| `1.3.6.1.2.1.2.2.1.10.N`    | ifInOctets    | Counter32. Only when the row has a counter                                                                                         |
| `1.3.6.1.2.1.2.2.1.16.N`    | ifOutOctets   | Counter32. Only when the row has a counter                                                                                         |
| `1.3.6.1.2.1.31.1.1.1.1.N`  | ifName        | `wired`, `backhaul`, `wl0`, `WAN`, `LAN1`                                                                                          |
| `1.3.6.1.2.1.31.1.1.1.6.N`  | ifHCInOctets  | Counter64. Only when the row has a counter                                                                                         |
| `1.3.6.1.2.1.31.1.1.1.10.N` | ifHCOutOctets | Counter64. Only when the row has a counter                                                                                         |
| `1.3.6.1.2.1.31.1.1.1.15.N` | ifHighSpeed   | Speed in Mbit/s                                                                                                                    |
| `1.3.6.1.2.1.31.1.1.1.18.N` | ifAlias       | The radio label (`wl-5.0G`), `wired`, `backhaul`, or the router's own port label. `(derived)` follows it when the row has counters |

`ifOperStatus` and the speed by row:

| Row           | `ifOperStatus`                                                   | Speed                                                               |
| ------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------- |
| `wired`       | `1` while a source counts the traffic, else `4` (unknown)        | `0`                                                                 |
| `backhaul`    | `1`, or `4` when the medium is unknown                           | The link rate. A wireless link uses the larger of the two PHY rates |
| radio         | `1` when the radio is on, else `2` (down)                        | `0`                                                                 |
| Ethernet port | `1` or `2` from the link state, `4` when the router does not say | The link rate of the port, `0` when unknown                         |

The counters are Counter32 and Counter64 values of the same total, so Counter32 wraps at 2^32.
LibreNMS prefers the 64-bit counters.

### Counter sources

The router reports traffic as rates for AiMesh data, and as byte counters for the device that you log
in to. The proxy turns both into octet counters, and keeps them in `counters.json`.

- **Rate source.** The root reports a rate for each link of an AiMesh node. The proxy adds
  `rate × interval` to the counter after each poll.
- **Byte source.** A device that you log in to reports byte counters for its interfaces: the root,
  a standalone device, and, in `per_node` mode, each node. The proxy adds the bytes that moved since
  the last poll. These counters win over rates for the same link.
- **Restarts.** A restart keeps the saved value. It skips only the interval that it did not see.
- **Gaps.** An interval longer than `collector.stale_after_s` adds nothing. Downtime never adds
  traffic.
- **Resets.** A byte counter that goes back (a reboot, or a 32-bit wrap on old firmware) adds nothing
  for that poll. The served counter holds its value for one sample.
- The proxy serves a counter from the first sample on. The first sample adds 0 bytes.

Radio rows (`wl<unit>`) take the byte source when the device has one, else the rate source. The
`wired` row is the wired total of the device. On a node it is the total of the node's client-facing
ports. The `backhaul` row is the traffic of the uplink of a node.

A total goes onto an Ethernet row only when it covers that port alone. The rules, in order:

1. **WAN, own counter.** The `WAN` row takes the WAN counter of the device itself when the WAN link is
   up and the device has one WAN port.
2. **WAN, wired uplink.** The `WAN` row of a node takes the `backhaul` counters. This needs a wired
   uplink on the WAN port, and the WAN link up.
3. **One port up, own total.** A device that you log in to reports one total for all its wired ports.
   That total goes onto the only port that is up. On a router, the WAN port does not count when
   rule 1 already gives it a counter.
4. **One client port up, AiMesh total.** The AiMesh total of a node's client ports goes onto the only
   LAN port that is up. This needs an uplink that is not a LAN port, and a port with no counter yet.
5. **Otherwise.** The port has no counter. The row keeps its link state and speed. The proxy serves no
   `0` in place of a counter. For ports that are up, it logs once for each change, at level `INFO`:
   `NAME: no counter of its own for WAN, LAN1 (one total covers several ports, or none measures it)`.

A row that carries counters has `(derived)` at the end of `ifAlias`.

## Clients per band

LibreNMS reads the number of clients, the channel, and the client link rates from NET-SNMP-EXTEND-MIB
rows. The rows have the layout of the LibreNMS `asuswrt-merlin` OS. The proxy does not run a script:
it serves the rows.

| Name                             | OID base                       | Value                                                              |
| -------------------------------- | ------------------------------ | ------------------------------------------------------------------ |
| `interfaces`                     | `1.3.6.1.4.1.8072.1.3.2.3.1.2` | One line per radio, such as `wl0,wl-2.4G`, separated by line feeds |
| `clients-wlan`                   | `1.3.6.1.4.1.8072.1.3.2.3.1.1` | The clients on all radios                                          |
| `clients-wl<unit>`               | `1.3.6.1.4.1.8072.1.3.2.3.1.1` | The clients on that radio                                          |
| `frequency-wl<unit>`             | `1.3.6.1.4.1.8072.1.3.2.3.1.1` | The channel frequency in MHz. Served when the channel is known     |
| `rate-tx-wl<unit>-{min,avg,max}` | `1.3.6.1.4.1.8072.1.3.2.3.1.1` | Client transmit rates in bit/s                                     |
| `rate-rx-wl<unit>-{min,avg,max}` | `1.3.6.1.4.1.8072.1.3.2.3.1.1` | Client receive rates in bit/s                                      |

The OID of a row is the base, then the length of the name, then each byte of the name. For
`clients-wl0` it is `1.3.6.1.4.1.8072.1.3.2.3.1.1.11.99.108.105.101.110.116.115.45.119.108.48`.
Use `snmpwalk` and the net-snmp MIB to read the names:

```sh
snmpwalk -v2c -c COMMUNITY 127.0.0.1:16102 1.3.6.1.4.1.8072.1.3.2.3.1.1
```

```text
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."clients-wl0" = STRING: 3
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."clients-wl1" = STRING: 0
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."clients-wlan" = STRING: 3
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."frequency-wl0" = STRING: 2437
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."frequency-wl1" = STRING: 5745
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."rate-rx-wl0-avg" = STRING: 51050000
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."rate-rx-wl0-max" = STRING: 130000000
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."rate-rx-wl0-min" = STRING: 1000000
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."rate-tx-wl0-avg" = STRING: 80400000
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."rate-tx-wl0-max" = STRING: 144400000
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."rate-tx-wl0-min" = STRING: 1000000
```

How the proxy counts:

- A client counts when it is online, connects over Wi-Fi, and the root assigns it to this device.
- A client counts on the radio of its link. A client that reports only a frequency counts on the
  lowest-numbered radio of that frequency. On a tri-band node with two 5 GHz radios, such a client
  lands on the first of them.
- The rate rows appear only for a radio with at least one client. The minimum, average, and maximum
  cover the clients that report a rate.
- A radio with no client serves `clients-wl<unit>` as `0` and no rate rows.

LibreNMS turns the rows into wireless sensors:

- `clients` for each radio, and a `wlan` total when the device has two or more radios.
- `frequency` for each radio that has one.
- `rate` for each radio with all six rate values.

LibreNMS never gets SNR or noise floor: the proxy serves neither. The `selftest` command lists the
sensors that LibreNMS would create.

## LLDP neighbors

The proxy serves LLDP-MIB (`1.0.8802.1.1.2`) so that LibreNMS draws the radio links between AiMesh
nodes. The device appears as one LLDP chassis. Its interfaces are the ports. Its radio links are the
remote systems.

| OID                                                | Object                                    | Value                                                                                       |
| -------------------------------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------------------- |
| `1.0.8802.1.1.2.1.3.1.0`, `1.0.8802.1.1.2.1.3.2.0` | lldpLocChassisIdSubtype, lldpLocChassisId | `4` (MAC address), and the device MAC                                                       |
| `1.0.8802.1.1.2.1.3.3.0`                           | lldpLocSysName                            | The served sysName                                                                          |
| `1.0.8802.1.1.2.1.3.7.1.{2,3,4}.N`                 | lldpLocPortTable                          | Port ID subtype `5` (interface name), the `ifName`, and the `ifAlias`. `N` is the `ifIndex` |
| `1.0.8802.1.1.2.1.4.1.1.{4..9}.0.N.K`              | lldpRemTable                              | The `K`-th neighbor on port `N`: chassis MAC, port ID, port description, and sysName        |
| `1.0.8802.1.1.2.1.4.2.1.{3,4}.0.N.K.1.4.A.B.C.D`   | lldpRemManAddrTable                       | The IPv4 address `A.B.C.D` of the neighbor                                                  |

- A wireless backhaul between two nodes gives one remote entry on each side: the child sees its
  parent on the `backhaul` port, and the parent sees the child on the parent's radio.
- The remote port is the `ifName` that the peer serves: `backhaul`, or `wl<unit>`. The remote sysName
  is the name that the peer serves.
- The proxy serves no entry for a wired uplink, because the switches already report those links. It
  serves none for a multi-link (MLO) backhaul, or when it cannot tell which radio of the parent the
  node uses.
- The proxy serves a management address only for an IPv4 address that is not loopback. It never
  serves `127.0.0.1`, because LibreNMS polls every device at that address.

## Differences by router type

The proxy detects the type from the AiMesh list.

- If the list holds nodes, the router with the role `router` is the **root** and the others are
  **nodes**.
- If the list is empty, the proxy serves the device that it logs in to as one root device. This
  covers a standalone router, an access point, and a media bridge.

| Item                             | AiMesh root                      | AiMesh node, `root_only`         | AiMesh node, `per_node`          | Standalone router, access point, media bridge |
| -------------------------------- | -------------------------------- | -------------------------------- | -------------------------------- | --------------------------------------------- |
| SNMP port                        | `port_base`                      | `port_base` + index              | `port_base` + index              | `port_base`                                   |
| Default sysName                  | `aimesh-root`                    | `aimesh-<6 hex>`                 | `aimesh-<6 hex>`                 | `aimesh-root`                                 |
| Router logins                    | one                              | none of its own                  | one more for each node           | one                                           |
| Uptime, CPU cores, RAM size      | yes                              | no                               | yes                              | yes, if the firmware reports them             |
| Temperatures, channel frequency  | yes                              | no                               | yes                              | yes                                           |
| CPU and memory percent           | yes                              | yes                              | yes                              | yes                                           |
| Traffic source                   | byte counters, then AiMesh rates | AiMesh rates                     | byte counters, then AiMesh rates | byte counters                                 |
| `backhaul` row and signal sensor | no                               | yes                              | yes                              | no                                            |
| LLDP neighbors                   | each wireless child              | its wireless parent and children | its wireless parent and children | none                                          |
| Clients                          | those the root assigns to it     | those the root assigns to it     | those the root assigns to it     | every online Wi-Fi client of the device       |

Notes:

- **Standalone router.** It serves as `aimesh-root`. It has no AiMesh list, so it has no AiMesh traffic
  rates, no backhaul, and no LLDP neighbors. Its WAN row takes the WAN counter of the device, when the
  WAN link is up.
- **Access point.** An access point reports no WAN counter, so its WAN row has no counters. The wired
  total goes onto the one port that is up, which is usually the uplink port.
- **Media bridge.** A media bridge has no Wi-Fi clients. The client counts are `0`, and LibreNMS
  creates no rate sensors. The radios, the channels, and the wired total still show.
- **AiMesh node.** In `root_only` mode a node serves no uptime, so `sysUpTime` counts from the start
  of serving. It serves no temperatures, no CPU cores, no RAM size, and no channel frequency. Use
  `per_node` for them. See [`[collector]`](configuration.md#collector).
- **Ports.** Which Ethernet ports exist, and how much each reports, depends on the model and the
  firmware. Some firmware versions give only the link state and a speed class. A port with no counter
  shows link state and speed. See [Counter sources](#counter-sources).
- **Several devices.** Each standalone device needs its own service. See
  [Instances](configuration.md#instances).

## What LibreNMS shows

| LibreNMS area                              | The proxy serves it as                                         |
| ------------------------------------------ | -------------------------------------------------------------- |
| Overview: OS, hardware, and version        | sysObjectID and the `ASUSWRT-Merlin <model> <firmware>` string |
| Overview: uptime, name, and location       | `sysUpTime`, `sysName`, and `sysLocation`                      |
| Health: processors, one for each core      | `hrProcessorLoad`                                              |
| Health: memory                             | The `hrStorageTable` row `Physical memory`                     |
| Health: temperature                        | ENTITY-SENSOR-MIB rows of type celsius                         |
| Health: dBm                                | ENTITY-SENSOR-MIB rows named `... Rx Power Sensor`             |
| Wireless sensors: clients, frequency, rate | NET-SNMP-EXTEND-MIB rows                                       |
| Ports and their traffic graphs             | IF-MIB and IF-MIB extension rows                               |
| Topology                                   | LLDP-MIB rows                                                  |

LibreNMS creates each sensor at its next discovery run. A sensor can appear late: a rate sensor,
for example, needs a client on the radio when discovery runs. See [LibreNMS](../librenms.md) for the
steps to add the devices.
