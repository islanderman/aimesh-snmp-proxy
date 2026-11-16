# AiMesh root with nodes

This guide serves an AiMesh network. LibreNMS gets one device for the root router and one for each
node. See [Choose your path](index.md) for the overview.

## 1. Prepare the router

1. Open the router web UI. Go to _Administration_, then _System_. Set _Authentication Method_ to
   `HTTPS` or `Both`. Note the HTTPS port. The default is 8443.
2. Reserve a fixed address for the root and for every node. Use the DHCP reservation list of the
   root.
3. Note the LAN address of the root, for example `192.168.50.1`.

## 2. Install the service

Follow [Installation](../installation.md). It leaves the service installed but not started. Stop
every service that polls this router.

## 3. Generate the config

```sh
APP=/opt/aimesh-snmp-proxy/venv/bin/aimesh-snmp-proxy
sudo $APP init --detect
```

`init` asks a few questions. Each shows its default in brackets, and Enter takes it. First it asks
for the instance name (leave it empty), the router address, the HTTPS port, and the admin user. Then
it asks for the router type (`auto` is right), the name that LibreNMS shows, the SNMP port base, and
the LibreNMS address (optional). If you give the address, `init` also asks which LibreNMS
certificate to pin (empty uses the system trust store) and writes the `[onboard]` table. It asks for
the admin password last, and the prompt does not echo. See [`init`](../reference/cli.md#init) for
every flag.

With `--detect`, `init` then fetches the root certificate and prints its SHA-256 fingerprint.
Compare it with the one your browser shows for `https://192.168.50.1:8443`. Type `yes` only if they
match. `init` logs in once, reads the AiMesh list, and puts the node addresses into
`nodes.expected`:

```text
detected: an AiMesh root with 2 nodes
  root  192.168.50.1  RT-EXAMPLE  online
  node  192.168.50.11  RT-EXAMPLE  online
  node  192.168.50.12  RT-EXAMPLE  online
```

It writes `config.toml`, `asus_password`, a random `snmp_community`, and `asus_router.pem` into
`/etc/aimesh-snmp-proxy`. It replaces the `config.toml` and the empty files that the installer
seeded. It replaces an edited config or a filled secret file only with `--force`, and a forced run
makes a new SNMP community. It prints the next steps.

To answer with flags instead, pass `--host`. To write the files yourself, see
[Write the config by hand](manual.md).

## 4. Run the installer again

The unit reads `asus.host`. Run the installer again from the bundle folder, so the unit can reach
the address you gave. Stop every service first.

```sh
cd /usr/local/src/aimesh-snmp-proxy-VERSION
sudo ./deploy/install.sh
```

## 5. Optional: serve per-node detail

With the default mode `root_only`, a node shows what the root knows about it. That is the model,
radios, clients, ports, backhaul, and traffic rates, plus one CPU row and a memory percentage. Its
uptime counts from the moment the proxy began to serve it.

Switch to `per_node` for the real uptime, temperatures, per-core CPU, RAM, channel frequency, and
exact traffic counters of each node. The proxy then logs in to every node too, and each node has its
own budget of 6 logins per hour. You pin the node certificates first. The steps are in
[Write the config by hand](manual.md#5-aimesh-only-serve-per-node-detail). Run the installer again
after you change the config. See [Collector modes](../reference/configuration.md#collector-modes).

## 6. Check

Keep the service stopped while you run `discover` and `selftest`. They log in to the router, and a
second login clashes with a running service.

```sh
sudo $APP discover
sudo $APP check-config
sudo $APP selftest
```

`discover` prints one row for each device. The first columns are the served name, the SNMP port, the
model, the firmware, and the LAN address. The last columns are the end of the MAC address, the
online state, the AiMesh level, and the backhaul to the parent. The port is a preview. The service
pins the real port in `ports.json` at its first start.

```text
role    sys_name       port   model       firmware  ip             mac_tail  online  level  backhaul
router  aimesh-root    16101  RT-EXAMPLE  3.0.0.x   192.168.50.1   00:53:01  yes     0      -
node    aimesh-005311  16102  RT-EXAMPLE  3.0.0.x   192.168.50.11  00:53:11  yes     1      wireless 5g1 -52 dBm 866 Mbit/s via 00:53:01
node    aimesh-005312  16103  RT-EXAMPLE  3.0.0.x   192.168.50.12  00:53:12  yes     1      wired 1000 Mbit/s via 00:53:01
```

If `discover` prints `no AiMesh nodes read from ...`, see
[Troubleshooting](../troubleshooting.md#discover-finds-no-nodes).

`selftest` polls the router once. It starts a test engine for each device on a free port and asks it
over SNMP. It writes nothing. It also shows which wireless sensors LibreNMS will create. It exits 0
only when every device serves and every address in `nodes.expected` is a node.

```text
NODE           MODEL       ONLINE  STATE    OIDS
aimesh-root    RT-EXAMPLE  yes     serving   412
aimesh-005311  RT-EXAMPLE  yes     serving   388
aimesh-005312  RT-EXAMPLE  yes     serving   391
...
OK: all 3 nodes serve
```

## 7. Start the service

```sh
sudo systemctl enable --now aimesh-snmp-proxy
sudo journalctl -u aimesh-snmp-proxy -e
```

The log shows `engine on 127.0.0.1:16101` for each device, then `SERVING`. The first start pins a
port for each node in `ports.json`.

## 8. Add the devices to LibreNMS

Wait 6 minutes after the start, or 11 minutes in `per_node` mode, so the per-device detail is
present when LibreNMS first discovers a device. Then follow [LibreNMS](../librenms.md). In short:

```sh
sudo -u librenms /opt/librenms/lnms config:set icmp_check false
sudo $APP onboard
sudo $APP onboard --apply
sudo -u librenms /opt/librenms/lnms config:set icmp_check true
```

You need an API token and an `[onboard]` table first. You get the table when you give `init` the
LibreNMS address in step 3. Otherwise add it by hand. You create the token file yourself. See
[LibreNMS](../librenms.md).

## What you will see

LibreNMS shows the root and each node as a device with wireless sensors. Each one has ports for the
wired side and every radio, and rows for the WAN and LAN ports. A node also has a backhaul port. To
list the devices as wireless, see
[Show the devices as wireless](../librenms.md#show-the-devices-as-wireless).

For the data of each device, see
[Differences by router type](../reference/metrics.md#differences-by-router-type) and
[What LibreNMS shows](../librenms.md#what-librenms-shows). Ports that share a traffic total show
their link state but no traffic. See the
[FAQ](../faq.md#why-do-some-ethernet-ports-show-no-traffic).
