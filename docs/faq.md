# FAQ

## Which routers and firmware work?

The proxy targets stock ASUS firmware (ASUSWRT) with HTTPS admin login. It was built and tested
against a live AiMesh network: a root router, several nodes, and standalone devices in media-bridge
mode.

Other models and firmware versions may report different data. The proxy leaves out a value it does
not receive and never invents one. If the router answers HTTP 404 for a page the proxy needs, the
proxy reports `unsupported`.

Third-party firmware is untested. ASUSWRT-Merlin offers its own SNMP agent, so you may not need this
project there.

If your model misbehaves, open an issue with the model name and the firmware version. Leave out MAC
addresses.

## Do I need an AiMesh network?

No. The proxy serves four kinds of device:

| Device                 | LibreNMS devices               |
| ---------------------- | ------------------------------ |
| AiMesh root with nodes | One for the root, one per node |
| Standalone router      | One                            |
| Access point           | One                            |
| Media bridge           | One                            |

A device with an empty AiMesh list is served as one root node. See the
[onboarding guides](onboarding/index.md).

## Why is the LibreNMS OS called `asuswrt-merlin`?

The proxy imitates the LibreNMS OS `asuswrt-merlin`. It is the LibreNMS OS for ASUS routers. It
reads the standard MIBs plus the NET-SNMP extend output for wireless sensors. That gives you
wireless sensors without a custom OS. You can set the OS type to `wireless`. See
[LibreNMS](librenms.md#show-the-devices-as-wireless).

## Does the proxy change anything on my router?

No. It logs in, reads status pages, and logs out. A request guard refuses every page that is not on
a fixed list of read pages. See the [security model](security.md#router-link).

## Why must the proxy run on the LibreNMS host?

It listens on `127.0.0.1` only. LibreNMS adds each device with the address `127.0.0.1` and a port,
so the poller must run on the same host. With distributed pollers, run the proxy on the poller that
polls those devices.

A LibreNMS container sees its own loopback address, not the address of the host, unless it shares the
host network. A container setup is untested.

## Why do some Ethernet ports show no traffic?

Stock firmware reports no traffic per port. It reports totals: one for the wired side of a device,
and one for each radio. The proxy puts a total on a port only when that total covers that port alone.
Ports that share a total show their link state and speed, and no traffic.

The rules are:

- A device's own wired total covers every wired port. When exactly one port is up, that port gets it.
- The AiMesh total of a node covers its LAN ports. When exactly one LAN port is up, and it is not the
  uplink, that port gets it. The data does not say which LAN port carries the uplink.
- A WAN row gets counters only from a source that measures the WAN port alone: the device's own WAN
  counter, or a wired uplink on the WAN port.

When two LAN ports are up, neither gets a counter.

## Why does my media bridge show 0 clients?

A media bridge uses its radios to reach the main router. It serves no Wi-Fi clients. So 0 clients is
correct.

## Why did LibreNMS remove CPU cores or sensors?

A discovery ran while the service had no detail. Detail needs up to 5 minutes to return after a
restart. Wait 6 minutes after a restart, or 11 in `per_node` mode, before you run discovery. See
[Wait before you run discovery](librenms.md#wait-before-you-run-discovery).

## When do I need `per_node` mode?

Use `per_node` when you want the real uptime, temperatures, per-core CPU, RAM size, channel
frequency, and exact traffic counters of each node, and not only of the root. Without it, a node
shows one CPU row, a memory percentage, and an uptime that counts from the moment the proxy began to
serve it. `per_node` logs in to each node, so each node needs a pinned certificate. A standalone
device does not need it.

## How many router logins does the proxy use?

Each start logs in once for each device it logs in to. Each device has a budget of 6 logins per
hour. The state of that budget survives restarts. Restart the service as little as you can.

## Can I use the router web UI while the proxy runs?

Yes, but a login from your browser clashes with the proxy session. The router can then refuse the
proxy login. The proxy waits 2 to 5 minutes and tries again. Stop the service before you run
`discover` or `selftest`, because they log in too. `check-config` reads files only.

## Why does a port alias end in `(derived)`?

The router reports rates and running totals. LibreNMS expects octet counters. The proxy sums the
values into 64-bit counters, keeps them in `counters.json`, and marks the alias `(derived)`. The
counters never go backwards across a restart.

## Does it support SNMPv3?

Yes. Add an `[snmp.v3]` table with an authPriv user, and add `LoadCredential=` lines for its key
files. See the [configuration keys](reference/configuration.md#snmpv3). `onboard` adds v2c
devices only, so keep `community_file` too.

## Does it serve STP or wired LLDP links?

No. Stock firmware exposes no STP state. The LLDP table lists the wireless backhaul links between
nodes. Your switches already report wired links.

## How do I change the name of a node?

Add an `[[override]]` with `match` and `sys_name`, then restart the service. The node serves the new
sysName. LibreNMS keeps the hostname it was added with. Rename the device in LibreNMS if you want
both to match.

## Can I run it without systemd, or in a container?

It is untested. The systemd sandbox is part of the [security model](security.md). The installer
targets systemd hosts only.

## Is this project from ASUS?

No. It is an independent project. ASUS, AiMesh, and ASUSWRT are trademarks of ASUSTeK Computer Inc.
LibreNMS is a trademark of its owners. The project uses these names only to say what it works with.
