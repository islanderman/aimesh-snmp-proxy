# Command line

`aimesh-snmp-proxy` is one program with several commands. The installer puts it at
`/opt/aimesh-snmp-proxy/venv/bin/aimesh-snmp-proxy`. You can also run `python -m aimesh_snmp_proxy`.
The examples on this page use `APP` for the program path:

```sh
APP=/opt/aimesh-snmp-proxy/venv/bin/aimesh-snmp-proxy
sudo $APP -c /etc/aimesh-snmp-proxy/config.toml check-config
```

## Synopsis

```text
aimesh-snmp-proxy [-h] [--version] [-c CONFIG] COMMAND [options]
```

| Command                         | Purpose                                                         | Logs in to the router                        | Writes                  |
| ------------------------------- | --------------------------------------------------------------- | -------------------------------------------- | ----------------------- |
| [`init`](#init)                 | Writes a first config file and its secret files                 | only with `--detect`                         | The config folder       |
| [`discover`](#discover)         | Lists the nodes, pins certificates, captures fixtures           | for the list, `--fixtures`, and `--node MAC` | A pin file or a fixture |
| [`check-config`](#check-config) | Checks the config, the secret files, the pins, and `ports.json` | no                                           | nothing                 |
| [`selftest`](#selftest)         | Polls the router once, then asks each node over SNMP            | yes, read-only                               | nothing                 |
| [`run`](#run)                   | The service: polls the router and serves SNMP                   | yes                                          | The state files         |
| [`onboard`](#onboard)           | Adds the devices to LibreNMS, or removes them                   | no                                           | `onboarded.json`        |
| [`dump-snmprec`](#dump-snmprec) | Prints the OIDs that a snapshot file renders                    | no                                           | nothing                 |

A normal setup runs them in this order: `init`, `discover --pin-cert`, `check-config`, `selftest`,
`run` (through systemd), and `onboard`.

## Global options

| Option                     | Meaning                                                                                      |
| -------------------------- | -------------------------------------------------------------------------------------------- |
| `-h`, `--help`             | Prints help and exits with code 0.                                                           |
| `--version`                | Prints `aimesh-snmp-proxy X.Y.Z` and exits with code 0.                                      |
| `-c FILE`, `--config FILE` | The config file. Default: `$AIMESH_PROXY_CONFIG`, else `/etc/aimesh-snmp-proxy/config.toml`. |

- `-c` works before or after the command. If you give it twice, the later one wins.
- Every command except `dump-snmprec` and `init` loads the config first. A missing or wrong file
  exits with code 78 before the command starts. So `COMMAND --help` needs a loadable config too:
  pass `-c`.
- `dump-snmprec` reads a config only when you give `-c` or set `AIMESH_PROXY_CONFIG`. `init` reads
  none.
- Run the commands that read secrets with `sudo`: the files sit in a root-only folder. `run` is the
  exception. It refuses to start as root.

## Exit codes

| Code | Meaning      | When                                                                                                                                                                                                                                                       |
| ---- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `0`  | Success      | The command did its job. `onboard` without `--apply` prints its plan and exits with 0. `run` exits with 0 after SIGTERM or SIGINT.                                                                                                                         |
| `1`  | Failed       | The command ran and failed: a node does not serve (`selftest`), the router cannot be read (`discover`), LibreNMS refused or stopped the run (`onboard`), a task failed (`run`), you did not confirm a pin, or the input file is unusable (`dump-snmprec`). |
| `2`  | Usage error  | An unknown command or option, a missing argument, or a combination that the command refuses, such as `onboard --force --remove`. The program prints a usage text.                                                                                          |
| `78` | Config error | The config file, a secret file, a pin file, or `ports.json` is missing or wrong, or `run` starts as root. The value is `EX_CONFIG` from sysexits. The unit sets `RestartPreventExitStatus=78`, so systemd does not restart the service after it.           |

An error line goes to standard error. A config error starts with `config error:`, and a damaged
`ports.json` gives `state error:`. See [Error messages](configuration.md#error-messages).

## `check-config`

```text
aimesh-snmp-proxy [-c FILE] check-config
```

Checks the config file, every secret file the daemon reads, the router pin, the node CA pin, the
pin of each override, and `ports.json`. It opens no network connection and changes nothing. It does
not read the `[onboard]` token.

| Option | Meaning                     |
| ------ | --------------------------- |
| `-c`   | The config file. See above. |

The output has no secret value and no MAC address:

```text
config ok: /etc/aimesh-snmp-proxy/config.toml
router: 192.168.50.1 port 8443 over HTTPS, pin SHA256:AA:BB:CC:DD:...:77:88:99
snmp: 127.0.0.1, root port 16101, v2c community file, v3 off
nodes: 2 expected (ports 16102-16103), 1 override(s)
collector: root_only, stale after 180 s
state: /var/lib/aimesh-snmp-proxy
ports.json: 2 pinned (ports 16102-16103)
onboard: https://192.168.50.10 (onboard checks its token and ca_file)
secret files: 2 ok (owner-only)
```

| Line           | Meaning                                                                                     |
| -------------- | ------------------------------------------------------------------------------------------- |
| `router`       | The address, the port, and the SHA-256 fingerprint of the pinned certificate                |
| `node CA`      | Shown when `asus.node_ca_file` is set: its fingerprint, and whether `per_node` mode uses it |
| `node pin`     | One line for each override that has a `ca_file`                                             |
| `snmp`         | The bind address, the root port, and which SNMP versions are on                             |
| `nodes`        | The number of reserved ports and the number of overrides                                    |
| `ports.json`   | The nodes that already have a pinned port                                                   |
| `onboard`      | Shown when `[onboard]` exists                                                               |
| `secret files` | How many secret files passed the owner and mode checks                                      |

Exit codes: `0` when all checks pass, `78` otherwise.

## `discover`

```text
aimesh-snmp-proxy [-c FILE] discover [--fixtures DIR]
                                     [--pin-cert PATH [--node ADDRESS]]
                                     [--pin-node-ca PATH] [--yes]
```

With no option, `discover` logs in to the root router once and lists the nodes that it reports.
It only reads. Give at most one of the other actions.

| Option               | Meaning                                                                                                        |
| -------------------- | -------------------------------------------------------------------------------------------------------------- |
| `--fixtures DIR`     | Polls the router once, prints the list, and saves the scrubbed replies to `DIR/fixture.json`.                  |
| `--pin-cert PATH`    | Fetches the router certificate, shows its fingerprint, and saves it to `PATH` as the pin.                      |
| `--node ADDRESS`     | With `--pin-cert`: pins the certificate of one AiMesh node instead. `ADDRESS` is the node MAC or IPv4 address. |
| `--pin-node-ca PATH` | Fetches a node's certificate chain, shows the CA that issued it, and saves that CA to `PATH`.                  |
| `--yes`              | With `--pin-cert` or `--pin-node-ca`: saves without asking.                                                    |

`--node` without `--pin-cert` is a usage error (exit 2). If you combine actions, the first match in
this order wins: `--pin-cert` with `--node`, `--pin-cert`, `--pin-node-ca`, then the list.

### List the nodes

```sh
sudo $APP -c /etc/aimesh-snmp-proxy/config.toml discover
```

```text
role    sys_name       port   model     firmware           ip             mac_tail  online  level  backhaul
router  aimesh-root    16101  RT-AX88U  3.0.0.4.388_00000  192.168.50.1   00:53:01  yes     0      -
node    aimesh-005311  16102  RT-AX86U  3.0.0.4.388_00000  192.168.50.11  00:53:11  yes     1      wireless 5g1 -58 dBm 866 Mbit/s via 00:53:01
node    aimesh-node-b  16103  RT-AX86U  3.0.0.4.388_00000  192.168.50.12  00:53:12  yes     1      wired 1000 Mbit/s via 00:53:01
```

| Column     | Meaning                                                                                     |
| ---------- | ------------------------------------------------------------------------------------------- |
| `role`     | `router` for the root, `node` for an AiMesh node                                            |
| `sys_name` | The name that the node serves as sysName                                                    |
| `port`     | The SNMP port of the node. A node without a pin yet shows the port that `run` will give it. |
| `model`    | The model name from the AiMesh list                                                         |
| `firmware` | The firmware version                                                                        |
| `ip`       | The LAN address                                                                             |
| `mac_tail` | The last three bytes of the node MAC. The list never shows a full MAC.                      |
| `online`   | `yes` or `no`, as the root reports                                                          |
| `level`    | The AiMesh hop count. The root is `0`.                                                      |
| `backhaul` | The uplink: medium, band, signal, link rate, and the parent (`via`). `-` for the root.      |

- A router with no AiMesh list (a standalone router, an access point, or a media bridge) lists one
  line: the device itself.
- The command never creates `ports.json`. A `port` for a new node is a preview.
- If the proxy reads no nodes, it prints `discover: no AiMesh nodes read from HOST: REASON` and
  exits with 1.

### Save a scrubbed capture

```sh
sudo $APP -c /etc/aimesh-snmp-proxy/config.toml discover --fixtures /tmp/capture
```

The command polls the router once and writes `DIR/fixture.json`. A key allowlist keeps only numbers,
flags, MAC addresses, and short model text. It drops SSIDs, host names, client names, IP addresses,
passwords, and tokens. It replaces every MAC address with an alias of the form
`02:00:00:00:xx:yy`. It never keeps the login exchange. Read the file before you share it.

### Pin the router certificate

```sh
sudo $APP -c /etc/aimesh-snmp-proxy/config.toml discover \
  --pin-cert /etc/aimesh-snmp-proxy/asus_router.pem
```

```text
192.168.50.1:8443 presents certificate SHA256:AA:BB:CC:DD:...:77:88:99
Check the fingerprint on the router itself before you trust it.
Type yes to pin this certificate: yes
pinned: /etc/aimesh-snmp-proxy/asus_router.pem (set [asus] ca_file to this path)
```

- The command makes a TLS handshake only. It sends no login.
- It writes the file with mode `0644` after you type `yes` or pass `--yes`. Any other answer prints
  `not pinned` and exits with 1.
- If `PATH` already holds this certificate, the command prints `already pinned: PATH` and exits
  with 0. If `PATH` holds another certificate, the command shows its fingerprints and asks again.

### Pin one node certificate

```sh
sudo $APP -c /etc/aimesh-snmp-proxy/config.toml discover \
  --pin-cert /etc/aimesh-snmp-proxy/node-12.pem --node 192.168.50.12
```

The command pins the node's own certificate. Name the file in the node's `[[override]]` as
`ca_file`. With an IPv4 address it makes a handshake only. With a MAC it logs in to the root once
to read the node IP. Asking for the root with `--node` is an error: pin the root without `--node`.

### Pin the CA of the node certificates

```sh
sudo $APP -c /etc/aimesh-snmp-proxy/config.toml discover \
  --pin-node-ca /etc/aimesh-snmp-proxy/asus_node_ca.pem
```

- The command needs `nodes.expected`. It makes a handshake with the first node that answers, and
  takes the CA from the certificate chain.
- If the node sends no issuing CA, the command tries `/cert.crt` on the root, over the pinned router
  certificate. Run `--pin-cert` first for this case. It accepts that file only when the one CA in it
  issued both the root certificate and the node certificate.
- It shows the subject and the fingerprint of the CA, then saves it after you confirm. Set the saved
  file as `asus.node_ca_file`.
- It warns when the node certificate does not name the node address.

Exit codes:

- `0` on success.
- `1` when the router, a node, or a certificate cannot be read, or you did not confirm a pin.
- `78` on a config error. This includes `--pin-node-ca` with no `nodes.expected`.
- `2` on a usage error.

## `selftest`

```text
aimesh-snmp-proxy [-c FILE] selftest
```

A read-only check of the whole chain. It takes no option besides `-c`.

1. It logs in to the router and polls it once, as `run` does. In `per_node` mode it also logs in to
   each node.
2. For each node it starts a test SNMP engine on a free loopback port outside the service range, so
   a running service is not disturbed.
3. It asks each engine for `sysObjectID`, `sysName`, and `sysDescr`, then walks the subtree `1.3.6`.
4. It replays the LibreNMS wireless discovery on the walk and lists the sensors it would create.

It writes nothing. It works on a scratch copy of `lockout.json`, so a router latch still blocks the
login, and `ports.json` stays as it is. Stop the service before you run it: the second login can
clash with the session of the service.

```text
selftest: one read-only poll of 192.168.50.1; test engines on 127.0.0.1 outside the service ports; nothing is written

NODE           MODEL     ONLINE  STATE    OIDS
aimesh-root    RT-AX88U  yes     serving   150
aimesh-005311  RT-AX86U  yes     serving   120
aimesh-node-b  RT-AX86U  no      silent      -

aimesh-root: sysObjectID .1.3.6.1.4.1.8072.3.2.10; sysDescr ASUS RT-AX88U stock 3.0.0.4.388_00000 via aimesh-snmp-proxy
  wireless created: clients wl0 wl1 wlan; frequency wl0 wl1; rate wl0
  wireless omitted: rate wl1 (no clients); snr, noise-floor (never served)
aimesh-005311: sysObjectID .1.3.6.1.4.1.8072.3.2.10; sysDescr ASUS RT-AX86U stock 3.0.0.4.388_00000 via aimesh-snmp-proxy
  wireless created: clients wl0 wl1 wlan; frequency wl0 wl1; rate wl0
  wireless omitted: rate wl1 (no clients); snr, noise-floor (never served)
aimesh-node-b: silent: no snapshot
FAIL: 2 of 3 nodes serve
```

| Column   | Meaning                                                              |
| -------- | -------------------------------------------------------------------- |
| `ONLINE` | What the root reports for the node: `yes`, `no`, or `-`              |
| `STATE`  | `serving` when the node answers over SNMP, `silent` when it does not |
| `OIDS`   | The number of OIDs in that walk. The LLDP rows are not in it         |

The `wireless omitted` line says why LibreNMS does not create a sensor. The reason is one of
`missing`, `channel unknown`, `no clients`, `rate unknown`, `N of 6 values`, or `never served`. See
[Clients per band](metrics.md#clients-per-band).

Exit codes: `0` only when every node serves and no expected node is missing from the AiMesh list.
`1` when a node fails, an expected node is absent, or the router gives no list (`FAIL: ...` is the last
line). `78` on a config error.

## `run`

```text
aimesh-snmp-proxy [-c FILE] run
```

The service. It takes no option besides `-c`. Start it through systemd:

```sh
sudo systemctl enable --now aimesh-snmp-proxy
```

The unit runs it as a throwaway user. By hand, it needs a user that can read the secret files and
write `state_dir`, and a second router login can clash with the service.

What it does:

1. It refuses to run as root (UID 0) or as the user `librenms`. Exit code 78.
2. It reads the secret files, the router pin, and `ports.json`. A problem gives exit code 78.
3. It logs in to the router, reads the AiMesh list, and polls on the cadence of `[collector]`.
4. Once a second it gives each node in the AiMesh list an SNMP engine on its pinned port. A port
   that is busy is retried with a growing delay, from 5 up to 60 seconds. The proxy never swaps in
   another node's port.
5. An engine answers only while its node has fresh data. A node whose data is stale or missing stays
   silent.

Signals:

| Signal              | Effect                                                                                                                      |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `SIGTERM`, `SIGINT` | Stops. It logs out of the router, saves `counters.json`, and closes the sockets.                                            |
| `SIGHUP`            | Re-reads the password file and clears the login latches. See `lockout.json` in [State files](configuration.md#state-files). |

The stop waits up to 20 seconds for the collector. The unit allows 30 seconds (`TimeoutStopSec=30`).

Exit codes: `0` after a clean stop, `1` when a task failed, `78` on a config error.

The service logs one JSON object per line to standard error. See
[Logging](configuration.md#logging) for the level.

## `onboard`

```text
aimesh-snmp-proxy [-c FILE] onboard [--dry-run | --apply] [--force] [--remove] [--allow-http]
```

Adds each node that the proxy serves to LibreNMS through its API, or removes the devices that it
added. It sends nothing unless you pass `--apply`.

| Option         | Meaning                                                                                                                                                           |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--dry-run`    | Prints the planned API calls and sends nothing. This is the default.                                                                                              |
| `--apply`      | Sends the API calls.                                                                                                                                              |
| `--force`      | Adds with `force_add=true`, which skips the LibreNMS checks. The command first asks the node over SNMP itself, and adds only when it answers with the right name. |
| `--remove`     | Deletes the devices that `state_dir/onboarded.json` lists, and nothing else.                                                                                      |
| `--allow-http` | Accepts an `http://` URL in `[onboard] url`. The API token then travels in cleartext.                                                                             |

`--force` does not combine with `--remove` (usage error, exit 2).

What you need before you run it:

- The service ran at least once, so `ports.json` holds a port for each node. `onboard` reads the
  plan from `ports.json` and the config. It does not log in to the router.
- An `[onboard]` table with `token_file`, and `snmp.community_file`. `onboard` adds v2c devices only.
- A LibreNMS API token. The user needs the right to create devices, and to delete them for
  `--remove`.

Each device that `onboard` adds has these fields:

| Field              | Value                                                                   |
| ------------------ | ----------------------------------------------------------------------- |
| `hostname`         | The served sysName, or the node LAN IP with `[onboard] hostname = "ip"` |
| `display_template` | `AiMesh root NAME` for the root, `AiMesh NAME` for a node               |
| `overwrite_ip`     | `127.0.0.1`                                                             |
| `port`             | The SNMP port of the node                                               |
| `transport`        | `udp`                                                                   |
| `snmpver`          | `v2c`                                                                   |
| `os`               | `asuswrt-merlin`                                                        |

Rules:

- It adds a node only when no LibreNMS device has its hostname and none sits at its SNMP endpoint
  (`127.0.0.1` and the port). A device that you renamed is not added twice.
- It never changes a device that exists.
- It skips a node, and says why, when an override excludes it, when two nodes would get the same
  hostname, or when the hostname is all digits (the API reads that as a device id). With
  `hostname = "ip"` it also skips a node that has no IPv4 address.
- An override that matches by an IP outside `nodes.expected`, and has no `port`, hides which node it
  names: `onboard` cannot tell without a router login. It prints a warning. Match such a node by MAC.
- With `--apply` it writes `onboarded.json` right after each create. `--remove` finds each device by
  its id, so it also removes a device that you renamed. It keeps a device that moved to another
  endpoint.
- LibreNMS reads `icmp_check` only when it creates a device, and every node shares `127.0.0.1`. Turn
  ICMP off before `--apply`, and on again after it:

```sh
sudo -u librenms /opt/librenms/lnms config:set icmp_check false
sudo $APP -c /etc/aimesh-snmp-proxy/config.toml onboard --apply
sudo -u librenms /opt/librenms/lnms config:set icmp_check true
```

A dry run prints the ICMP steps, the planned calls, and a plan table:

```text
onboard: dry run; nothing is sent to https://192.168.50.10

ICMP: the LibreNMS API cannot turn ICMP off for one device. Every node
shares overwrite_ip 127.0.0.1, so LibreNMS would file all their ping results
under one device. LibreNMS reads icmp_check only when it creates a device;
on the LibreNMS host, as the librenms user, run:
  before --apply:  lnms config:set icmp_check false
  after --apply:   lnms config:set icmp_check true
Devices created in between keep ICMP off. Web UI: Settings > Poller > Ping
(/settings/icmp_check); per device afterwards: Edit device > Polling > ICMP.

Planned API calls, in port order; a node that exists stops at its GET:
  GET  /api/v0/devices  (once: a node already at 127.0.0.1:PORT is left alone)
  GET  /api/v0/devices/aimesh-root
  POST /api/v0/devices {"community": "***", "display_template": "AiMesh root aimesh-root", "hostname": "aimesh-root", "os": "asuswrt-merlin", "overwrite_ip": "127.0.0.1", "port": 16101, "snmpver": "v2c", "transport": "udp"}
  (the same GET and POST for each node)

PORT   ROLE  HOSTNAME       PLAN
16101  root  aimesh-root    add (checked)
16102  node  aimesh-005311  add (checked)
16103  node  aimesh-node-b  add (checked)

Run again with --apply to send these calls.
```

If LibreNMS refuses a checked add, the result column says `refused`, and the command suggests
`--force`. To undo, run `onboard --remove` (a dry run), then `onboard --apply --remove`.

Exit codes:

- `0` on success and for any dry run.
- `1` when a call fails, LibreNMS refuses an add, the run stops (a bad token, an unreachable
  server), or `--remove` keeps a device that moved.
- `78` on a config error: `[onboard]` missing, an `http://` URL without `--allow-http`, or an
  unreadable `onboarded.json` or `ports.json`.
- `2` on a usage error.

See [LibreNMS](../librenms.md) for the full steps.

## `dump-snmprec`

```text
aimesh-snmp-proxy [-c FILE] dump-snmprec --snapshot FILE [--profile NAME]
```

Prints the OIDs that a snapshot file renders, in `snmprec` format. It needs no router and no
config. Use it to see what a device would serve, or to compare with a LibreNMS test fixture.

| Option            | Meaning                                                                 |
| ----------------- | ----------------------------------------------------------------------- |
| `--snapshot FILE` | A snapshot as JSON. Required. At most 1 MiB.                            |
| `--profile NAME`  | The MIB profile. Default: the one in the config, else `asuswrt-merlin`. |

The snapshot has the fields of one node. The loader is strict: an unknown key, a null in a required
field, and a wrong type are errors. This file is the smallest useful snapshot:

```json
{
  "node_id": "00:00:5e:00:53:01",
  "sys_name": "aimesh-root",
  "mac": "00:00:5e:00:53:01",
  "online": true,
  "role": "router",
  "level": 0,
  "collected_at": 0.0,
  "model": "RT-AX88U",
  "firmware": "3.0.0.4.388_00000",
  "uptime_s": 3600,
  "radios": [{ "unit": 0, "band": "2g1", "mac": "00:00:5e:00:53:10", "state": true, "clients": 2 }]
}
```

```sh
aimesh-snmp-proxy dump-snmprec --snapshot snapshot.json
```

```text
1.3.6.1.2.1.1.1.0|4|ASUS RT-AX88U stock 3.0.0.4.388_00000 via aimesh-snmp-proxy
1.3.6.1.2.1.1.2.0|6|1.3.6.1.4.1.8072.3.2.10
1.3.6.1.2.1.1.3.0|67|360000
1.3.6.1.2.1.1.5.0|4|aimesh-root
1.3.6.1.4.1.2021.7890.1.101.1|4|ASUSWRT-Merlin RT-AX88U 3.0.0.4.388_00000
...
```

Each line is `OID|tag|value`. The tag tells the type of the value:

| Tag  | Type                                                                         |
| ---- | ---------------------------------------------------------------------------- |
| `2`  | Integer                                                                      |
| `4`  | Text                                                                         |
| `4x` | Text in hex digits, for text that is not plain ASCII or that holds a newline |
| `6`  | OID                                                                          |
| `65` | Counter32                                                                    |
| `66` | Gauge32                                                                      |
| `67` | TimeTicks                                                                    |
| `70` | Counter64                                                                    |

See [Served metrics](metrics.md) for what each OID means.

Exit codes: `0` on success. `1` when the file is missing or invalid, or the profile is unknown. `2`
when `--snapshot` is missing. `78` when you give a config that fails to load.

## `init`

```text
aimesh-snmp-proxy init [--host IP] [--port PORT] [--username USER] [--password-stdin]
                       [--instance NAME] [--port-base PORT] [--mode MODE] [--nodes IPS]
                       [--sys-name NAME] [--librenms-url URL] [--librenms-ca PATH]
                       [--output-dir DIR] [--detect] [--yes] [--dry-run] [--force]
```

Writes `config.toml` and its secret files for one router. It reads no config, so `-c` is a usage
error: use `--output-dir`.

Flags answer every question. On a terminal, `init` without `--host` asks for each value that no
flag gave. Without a terminal, `--host` and `--password-stdin` are required.

| Option               | Default                                                             | Meaning                                                                                                           |
| -------------------- | ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `--host IP`          | none; a terminal suggests `192.168.50.1`                            | The router LAN IPv4 address                                                                                       |
| `--port PORT`        | `8443`                                                              | The HTTPS port of the router web UI                                                                               |
| `--username USER`    | `admin`                                                             | The router admin user                                                                                             |
| `--password-stdin`   | off; a terminal asks without echo                                   | Reads the router password from the first line of standard input. Refuses a terminal                               |
| `--instance NAME`    | none: the main service                                              | One more router: unit `aimesh-snmp-proxy@NAME`, folder `/etc/aimesh-snmp-proxy/NAME`, and its own block of ports  |
| `--port-base PORT`   | the first of 16101, 16201, ... whose 100 ports no other config uses | The root SNMP port, `snmp.port_base`                                                                              |
| `--mode MODE`        | `auto`; `aimesh` when `--nodes` is not empty                        | `auto`, `aimesh` (an AiMesh root), or `standalone` (a router, access point, or media bridge without AiMesh nodes) |
| `--nodes IPS`        | none                                                                | The AiMesh node IPs for `nodes.expected`, comma-separated. Ranges such as `192.168.50.11-14` work                 |
| `--sys-name NAME`    | `aimesh-root`; with `--instance`, `aimesh-NAME`                     | The sysName that LibreNMS shows. Any name but `aimesh-root` goes into an `[[override]]` on `asus.host`            |
| `--librenms-url URL` | none: no `[onboard]` table                                          | Adds an `[onboard]` table with this URL                                                                           |
| `--librenms-ca PATH` | none                                                                | Copies this LibreNMS certificate to `librenms.pem` and names it in `[onboard]`. Needs `--librenms-url`            |
| `--output-dir DIR`   | `/etc/aimesh-snmp-proxy`, or `/etc/aimesh-snmp-proxy/NAME`          | Where to write. A missing folder gets mode `0700`                                                                 |
| `--detect`           | off                                                                 | Pins the router certificate, then logs in once to tell an AiMesh root from a standalone device                    |
| `--yes`              | off                                                                 | With `--detect`: pins the certificate without asking                                                              |
| `--dry-run`          | off                                                                 | Checks the answers and prints the result. Writes nothing                                                          |
| `--force`            | off                                                                 | Replaces files that exist                                                                                         |

These flag combinations are usage errors: `--yes` without `--detect`, `--detect` with `--nodes`,
`--mode standalone` with `--nodes`, and `--librenms-ca` without `--librenms-url`.

### What `init` writes

| File              | Mode   | Content                                                      |
| ----------------- | ------ | ------------------------------------------------------------ |
| `asus_password`   | `0600` | The router password, from the prompt or from standard input  |
| `snmp_community`  | `0600` | A new random community of 32 hex digits                      |
| `librenms.pem`    | `0644` | A copy of the `--librenms-ca` file. Only with that option    |
| `asus_router.pem` | `0644` | The router certificate. Only with `--detect`                 |
| `config.toml`     | `0600` | The config. See [Configuration keys](configuration.md). Last |

- The password never comes from the command line. Pipe it in from a file that only you can read, as
  in the examples below.
- `init` writes with umask `077`. Each file is written in one step, and `config.toml` goes last,
  because it names the others.
- It checks the new config with the loader of `check-config` before it writes anything.
- It replaces no file without `--force`. A forced run prints `replaced: ...`, and it makes a new SNMP
  community, so LibreNMS devices that you added before need the new one.
- The installer seeds `config.toml` and empty secret files. Run `init` before the installer, with
  `scripts/generate-config.sh` from a source checkout, or run `init --force` after it.
- `--librenms-url` does not create `librenms_token`. Put the API token there before you run
  `onboard`.
- With `--instance`, `init` sets `state_dir` to `/var/lib/aimesh-snmp-proxy-NAME`. It reads the main
  config and the config of each instance in `/etc/aimesh-snmp-proxy`, and picks a `port_base` that
  none of them overlaps. A `--port-base` within 100 ports of another service is an error.
- `--mode auto` leaves `[nodes]` as a comment. `--mode aimesh` writes `[nodes] expected` from
  `--nodes`, or an empty list. `--mode standalone` writes no `[nodes]`.

### Detect the router type

`--detect` finds out what the router is, so that you do not list the nodes by hand.

- It pins the router certificate as `discover --pin-cert` does: a TLS handshake only, then the
  SHA-256 fingerprint, then the question `Type yes to pin this certificate`. `--yes` answers it.
  There is no question when the same certificate is already pinned.
- Then it logs in once and logs out. It only reads: the AiMesh list, or for a router without one,
  the Wi-Fi data of the device.
- On an AiMesh root it fills `nodes.expected` with the node IPs in address order. It leaves out a
  node that has no IP, with a warning. With no nodes it treats the router as a standalone device
  and writes no `[nodes]`.
- An explicit `--mode` wins. `init` warns when the router disagrees.
- Stop the service that polls the router first: the router takes one admin session. The proxy keeps
  to 6 router logins in one hour, and `--detect`, `discover`, and `selftest` each spend one.
- It keeps the login state in a temporary folder, so the `lockout.json` of the service stays as it
  is. A refused login exits with 1 and writes no config.
- With `--dry-run` it still logs in once, but writes nothing.

After the pin steps, `--detect` prints what it found:

```text
detected: an AiMesh root with 2 nodes
  root  192.168.50.1  RT-AX88U  online
  node  192.168.50.11  RT-AX86U  online
  node  192.168.50.12  RT-AX86U  online
```

For any other device it prints `detected: a standalone router, AP or media bridge`.

### Questions on a terminal

Each question shows its default in brackets, and Enter takes it. A flag that gave the answer skips
its question. A wrong answer is asked again, up to three times. Then `init` stops with exit code 2.
The questions come in this order:

1. The instance name. Empty means the main service.
2. The router IPv4 address.
3. The HTTPS port.
4. The admin user.
5. The router type. A `--mode` or a `--nodes` skips it.
6. Whether to log in once now to detect the type and the nodes. It is asked for `auto` and `aimesh`,
   without `--detect` and without `--nodes`.
7. The AiMesh node IPs. It is asked for `aimesh` without detection.
8. The sysName.
9. The SNMP port base.
10. The LibreNMS URL. Empty means no `[onboard]` table.
11. The LibreNMS certificate to pin. It is asked after a URL.
12. The router password, without echo.

With `--detect`, the question `Type yes to pin this certificate` comes last.

### Run `init`

The main service, with the password in a file that only you can read:

```sh
sudo $APP init --host 192.168.50.1 --password-stdin < router-password.txt
```

```text
wrote /etc/aimesh-snmp-proxy: asus_password, snmp_community, config.toml
config ok: snmp.port_base 16101 (node N serves 16101 + N), state_dir /var/lib/aimesh-snmp-proxy

Next steps (APP=/opt/aimesh-snmp-proxy/venv/bin/aimesh-snmp-proxy):
  1. sudo deploy/install.sh  (again if it ran before: the unit reads asus.host)
  2. sudo $APP -c /etc/aimesh-snmp-proxy/config.toml discover --pin-cert /etc/aimesh-snmp-proxy/asus_router.pem  (compare the fingerprint with the router's)
  3. sudo $APP -c /etc/aimesh-snmp-proxy/config.toml discover  (one router login: lists the nodes and their ports)
  4. sudo $APP -c /etc/aimesh-snmp-proxy/config.toml check-config
  5. sudo $APP -c /etc/aimesh-snmp-proxy/config.toml selftest  (with the service stopped)
  6. sudo systemctl enable --now aimesh-snmp-proxy
  7. add [onboard] (or re-run init with --librenms-url), then sudo $APP -c /etc/aimesh-snmp-proxy/config.toml onboard --apply
```

With `--output-dir`, a first step says to move the files to the folder that the installer reads.

A standalone access point as the instance `lab`, beside the main service:

```sh
sudo $APP init --host 192.168.50.2 --instance lab --mode standalone --password-stdin < router-password.txt
```

The command writes `/etc/aimesh-snmp-proxy/lab/config.toml`. The next steps then name
`install.sh --instance lab`, `-c /etc/aimesh-snmp-proxy/lab/config.toml`, and the unit
`aimesh-snmp-proxy@lab`. The config is:

```toml
# Written by aimesh-snmp-proxy init 0.3.0; check it: check-config.
# Relative *_file paths resolve against $CREDENTIALS_DIRECTORY (systemd
# LoadCredential=), else this file's folder. Secret files must be chmod 600.

# Must survive restarts: ports.json (port pins), counters.json, lockout.json.
state_dir = "/var/lib/aimesh-snmp-proxy-lab"

[asus]
host = "192.168.50.2"
port = 8443
use_ssl = true  # must stay true: HTTP sends the login in cleartext
username = "admin"
password_file = "asus_password"
ca_file = "asus_router.pem"  # the router certificate: discover --pin-cert

# A standalone router, AP or media bridge is one device: no [nodes].

[snmp]
bind = "127.0.0.1"  # the only accepted value
port_base = 16201  # root port; node N serves port_base + N
profile = "asuswrt-merlin"
community_file = "snmp_community"

[collector]
mode = "root_only"  # per_node adds one router login per node

[logging]
level = "INFO"

# The sysName LibreNMS shows for this router.
[[override]]
match = "192.168.50.2"
sys_name = "aimesh-lab"
```

A dry run prints the files and the config, and writes nothing:

```text
dry run: nothing written. /etc/aimesh-snmp-proxy would get:
  asus_password (0600): the router password
  snmp_community (0600): a new random SNMP community
  config.toml (0600):
# Written by aimesh-snmp-proxy init 0.3.0; check it: check-config.
...
config ok: check-config's loader accepts it
```

When a file exists, `init` stops and names the files:

```text
init: /etc/aimesh-snmp-proxy/lab already holds config.toml, asus_password, snmp_community: pass --force to replace (install.sh seeds config.toml and empty secret files)
```

### The wrapper script

`scripts/generate-config.sh` passes every argument to `aimesh-snmp-proxy init`. It looks for the
program in this order:

1. `$AIMESH_SNMP_PROXY`
2. `/opt/aimesh-snmp-proxy/venv/bin/aimesh-snmp-proxy`
3. `aimesh-snmp-proxy` on `PATH`
4. `uv run --frozen --project CHECKOUT aimesh-snmp-proxy init`, where `CHECKOUT` is the source
   checkout that holds the script

It exits with 127 when it finds none. Otherwise it exits with the code of `init`.

### Exit codes of `init`

- `0` when the files are written, or the dry run passes.
- `1` when `init` refuses or fails: a file exists and you gave no `--force`, a file or folder cannot be
  read or written, you declined the pin, the router is unreachable or refuses the login, or a
  config of another service cannot be read and you gave no `--port-base`.
- `2` on a usage error: a bad or conflicting flag, no `--host` or no password source without a
  terminal, a bad password, no valid answer, or input that ends at a question.
- `78` on a config error: the loader refuses the result (for example, a node IP listed twice),
  `--port-base` overlaps another service, or the `--librenms-ca` file is no PEM certificate.

## Environment variables

| Variable                         | Effect                                                                                         |
| -------------------------------- | ---------------------------------------------------------------------------------------------- |
| `AIMESH_PROXY_CONFIG`            | The config file when you give no `-c`.                                                         |
| `AIMESH_PROXY__<SECTION>__<KEY>` | Overrides one config key. See [Environment variables](configuration.md#environment-variables). |
| `CREDENTIALS_DIRECTORY`          | Set by systemd. Relative `*_file` paths resolve here.                                          |
| `STATE_DIRECTORY`                | Set by systemd. The default of `state_dir`.                                                    |
