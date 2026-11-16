# Write the config by hand

The guides use `init` to write the config. Use this page when you prefer to write the files
yourself, or when you need a key that `init` does not set. The steps are the same for every router
type. The notes mark what only an AiMesh root needs.

Install the service first. See [Installation](../installation.md). The installer leaves a copy of
`config.example.toml`, and the three empty files `asus_password`, `snmp_community`, and
`asus_router.pem`, in `/etc/aimesh-snmp-proxy`.

## 1. Write the secrets

The commands read a value without echo. They write it to a file that only root can read.

```sh
sudo bash -c 'umask 077; read -rsp "router password: " p; echo
  printf %s "$p" >"$0"' /etc/aimesh-snmp-proxy/asus_password
sudo sh -c 'umask 077; openssl rand -hex 16 >"$0"' \
  /etc/aimesh-snmp-proxy/snmp_community
```

The first command stores the admin password of the router. The second creates a random SNMP
community. LibreNMS gets it later through `onboard`.

## 2. Edit the config

```sh
sudo ${EDITOR:-nano} /etc/aimesh-snmp-proxy/config.toml
```

Set the address and the user name of the router:

```toml
[asus]
host = "192.168.50.1"
username = "admin"
```

For a standalone router, access point, or media bridge, delete the `[nodes]` table. The device has
no AiMesh nodes, and `selftest` fails for every address you list there. For an AiMesh root, delete
the `[nodes]` table for now and fill it in after step 4.

Run `sudo ./deploy/install.sh` again from the bundle folder. The installer lets the unit reach the
address you set. Stop every running service first.

The [configuration keys](../reference/configuration.md) page lists every other key.

## 3. Pin the router certificate

The proxy trusts only the certificate you pin. This command fetches it, prints its fingerprint, and
saves it after you type `yes`.

```sh
APP=/opt/aimesh-snmp-proxy/venv/bin/aimesh-snmp-proxy
sudo $APP discover --pin-cert /etc/aimesh-snmp-proxy/asus_router.pem
```

Compare the printed `SHA256:` fingerprint with the one your browser shows for
`https://192.168.50.1:8443`. Type `yes` only if they match.

## 4. List the nodes

```sh
sudo $APP discover
```

`discover` logs in once and reads the AiMesh list. It changes nothing on the router. It records its
login in `lockout.json`, so it counts against the budget of 6 logins per hour. It prints one row for
each device:

```text
role    sys_name       port   model       firmware  ip             mac_tail  online  level  backhaul
router  aimesh-root    16101  RT-EXAMPLE  3.0.0.x   192.168.50.1   00:53:01  yes     0      -
node    aimesh-005311  16102  RT-EXAMPLE  3.0.0.x   192.168.50.11  00:53:11  yes     1      wireless 5g1 -52 dBm 866 Mbit/s via 00:53:01
node    aimesh-005312  16103  RT-EXAMPLE  3.0.0.x   192.168.50.12  00:53:12  yes     1      wired 1000 Mbit/s via 00:53:01
```

The first columns are the served name, the SNMP port, the model, the firmware, and the LAN address.
The last columns are the end of the MAC address, the online state, the AiMesh level, and the backhaul
to the parent. The port is a preview. The service pins the real port in `ports.json` at its first
start.

A standalone router, access point, or media bridge shows one row, with the role `router`.

If `discover` prints `no AiMesh nodes read from ...`, see
[Troubleshooting](../troubleshooting.md#discover-finds-no-nodes).

For an AiMesh root, copy the addresses of the nodes into `[nodes]`. List the real nodes only.
`selftest` fails with `absent from the AiMesh list` for an address that is not a node.

```toml
[nodes]
expected = "192.168.50.11-12"
```

The order sets the port index. The first address gets `port_base + 1`, the second `port_base + 2`.
A node you do not list takes the next free index later.

## 5. AiMesh only: serve per-node detail

With the default mode `root_only`, a node shows what the root knows about it. That is the model,
radios, clients, ports, backhaul, and traffic rates, plus one CPU row and a memory percentage. Its
uptime counts from the moment the proxy began to serve it. Switch to `per_node` for the real uptime,
temperatures, per-core CPU, RAM, channel frequency, and exact traffic counters of each node. The
proxy then logs in to every node too. See
[Collector modes](../reference/configuration.md#collector-modes).

Pin the CA that issued the node certificates. The command asks a node for its chain and saves the
issuing CA after you type `yes`:

```sh
sudo $APP discover --pin-node-ca /etc/aimesh-snmp-proxy/asus_node_ca.pem
```

If a node sends only its own certificate, the proxy fetches the root's `/cert.crt`. It accepts that
file only when it holds one CA certificate that issued both the root and the node certificate.

The node CA does not cover a node with an old self-signed certificate. Pin that node's own
certificate and name the file in an override:

```sh
sudo $APP discover --pin-cert /etc/aimesh-snmp-proxy/node-12.pem --node 192.168.50.12
```

Then set these keys:

```toml
[asus]
node_ca_file = "asus_node_ca.pem"

[collector]
mode = "per_node"

[[override]]
match = "192.168.50.12"
ca_file = "node-12.pem"
```

Run `sudo ./deploy/install.sh` again. It adds the nodes to the unit's address list and loads each
pin as a credential. Each node has its own budget of 6 logins per hour.

## 6. Name the device

The proxy serves the name `aimesh-root` by default. `onboard` skips a device whose name already
exists in LibreNMS, so give each router its own name. Add an override whose `match` is the address
of the router:

```toml
[[override]]
match = "192.168.50.1"
sys_name = "home-router"
location = "Hallway"
```

## 7. Check

Keep the service stopped while you run `selftest`. It logs in to the router, and a second login
clashes with a running service.

```sh
sudo $APP check-config
sudo $APP selftest
```

`check-config` validates the files and prints a summary. It reads files only. It prints no secret and
no MAC address.

```text
config ok: /etc/aimesh-snmp-proxy/config.toml
router: 192.168.50.1 port 8443 over HTTPS, pin SHA256:AA:BB:CC:...
snmp: 127.0.0.1, root port 16101, v2c community file, v3 off
nodes: 2 expected (ports 16102-16103), 0 override(s)
collector: root_only, stale after 180 s
state: /var/lib/aimesh-snmp-proxy
ports.json: none pinned yet
secret files: 2 ok (owner-only)
```

`selftest` polls the router once. It starts a test engine for each device on a free port and asks it
over SNMP. It writes nothing. It also shows which wireless sensors LibreNMS will create.

```text
NODE           MODEL       ONLINE  STATE    OIDS
aimesh-root    RT-EXAMPLE  yes     serving   412
aimesh-005311  RT-EXAMPLE  yes     serving   388
aimesh-005312  RT-EXAMPLE  yes     serving   391
...
OK: all 3 nodes serve
```

It exits 0 only when every device serves and every expected node is present. Then start the
service. See the guide for your router type.
