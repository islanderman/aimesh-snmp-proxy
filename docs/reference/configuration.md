# Configuration keys

The proxy reads one TOML file. This page lists every key with its type, default, allowed values,
and purpose. Each section ends with a short example.

The loader is strict. It rejects an unknown key, a value of the wrong type, and a value out of
range. It never accepts a secret inside the file: each secret sits in its own file, and a `*_file`
key names that file. An error names the key and the path. It never prints a secret.

Run `check-config` after every edit. On a wrong file it prints one `config error:` line and exits
with code 78. See [Command line](cli.md#check-config).

## How the file is read

- The command line reads the file from `-c FILE`, else from `$AIMESH_PROXY_CONFIG`, else from
  `/etc/aimesh-snmp-proxy/config.toml`. The systemd unit passes its own copy:
  `${CREDENTIALS_DIRECTORY}/config.toml`. Restart the service after every edit.
- `state_dir` is the only key outside a table. Put it first, before any `[section]`.
- `[asus]` and `[snmp]` are required. `[nodes]`, `[snmp.v3]`, `[collector]`, `[logging]`, and
  `[onboard]` are optional. `[[override]]` repeats once for each node you change.
- A relative `*_file` path resolves against `$CREDENTIALS_DIRECTORY` when systemd sets it. Otherwise
  it resolves against the folder of the config file. An absolute path stays as it is.
- A key ends in `_s` when its value is in seconds. A number such as `2.5` is fine.
- An environment variable can override any key except `[[override]]`. See
  [Environment variables](#environment-variables).

The smallest valid file:

```toml
[asus]
host = "192.168.50.1"
username = "admin"
password_file = "asus_password"
ca_file = "asus_router.pem"

[snmp]
community_file = "snmp_community"
```

## Top level

| Key         | Type   | Default                                                              | Allowed values | Purpose                                     |
| ----------- | ------ | -------------------------------------------------------------------- | -------------- | ------------------------------------------- |
| `state_dir` | string | first entry of `$STATE_DIRECTORY`, else `/var/lib/aimesh-snmp-proxy` | absolute path  | Folder for files that must survive restarts |

- Under systemd, the unit lets the proxy write only to its own state folder. Keep the value that
  the installer writes.
- The folder holds the files in [State files](#state-files).

```toml
state_dir = "/var/lib/aimesh-snmp-proxy"
```

## `[asus]`

The router that the proxy logs in to. For an AiMesh network this is the root router. For a
standalone router, access point, or media bridge it is that device.

| Key             | Type    | Default        | Allowed values                           | Purpose                                           |
| --------------- | ------- | -------------- | ---------------------------------------- | ------------------------------------------------- |
| `host`          | string  | none, required | IPv4 address, IPv6 address, or host name | Address of the router                             |
| `port`          | integer | `8443`         | 1 to 65535                               | HTTPS port of the router web UI                   |
| `use_ssl`       | boolean | `true`         | `true`                                   | Keeps the login on HTTPS                          |
| `username`      | string  | none, required | one non-empty line                       | Router admin user name                            |
| `password_file` | path    | none, required | file name or path                        | File that holds the admin password                |
| `ca_file`       | path    | none, required | PEM file                                 | The router certificate that the proxy trusts      |
| `node_ca_file`  | path    | none           | PEM file of a CA                         | CA that issued the node certificates (`per_node`) |

- `host`: use the IPv4 address. The installer refuses a host name, because the systemd
  `IPAddressAllow=` setting takes no names. The proxy also uses the IPv4 address to find the root
  device.
- `port`: the proxy never speaks plain HTTP. Change `port` only if you moved the HTTPS port of the
  router web UI.
- `use_ssl`: `false` is an error, because plain HTTP would send the admin login in cleartext.
- `ca_file`: the proxy trusts this certificate and no other for the router. It compares the
  certificate itself, so the certificate need not name the router address. Create the file with
  `discover --pin-cert`. It holds PEM text, at most 64 KiB, and no private key.
- `node_ca_file`: with this file, a `per_node` session accepts a node only when this CA issued its
  certificate and the certificate names the node IP. The file must hold a CA certificate. Create
  it with `discover --pin-node-ca`. With `collector.mode = "root_only"` the proxy logs a warning and
  opens no node session.

```toml
[asus]
host = "192.168.50.1"
port = 8443
use_ssl = true
username = "admin"
password_file = "asus_password"
ca_file = "asus_router.pem"
node_ca_file = "asus_node_ca.pem" # optional; only for collector.mode = "per_node"
```

## `[nodes]`

| Key        | Type                      | Default | Allowed values                                           | Purpose                                    |
| ---------- | ------------------------- | ------- | -------------------------------------------------------- | ------------------------------------------ |
| `expected` | string or list of strings | empty   | IPv4 addresses and ranges; at most 255; no address twice | The AiMesh nodes you expect, in port order |

Each item is one of:

- `192.168.50.11`: one address.
- `192.168.50.11-19`: a range. The number after the dash replaces the last octet.
- `192.168.50.11-192.168.50.19`: a range with a full end address.

The order matters. The first address reserves SNMP port index 1, the second reserves index 2, and so
on. See [SNMP ports](#snmp-ports). In `per_node` mode the installer also lets the unit reach these
addresses.

Leave `[nodes]` out for a standalone router, access point, or media bridge.

```toml
[nodes]
expected = ["192.168.50.11-14", "192.168.50.20"] # a string works too: "192.168.50.11-14"
```

## `[snmp]`

The SNMP side. Set `community_file`, or add `[snmp.v3]`, or both. With neither, the proxy refuses
to start: `snmp: set community_file (v2c) or add [snmp.v3]`.

| Key              | Type    | Default          | Allowed values                       | Purpose                                 |
| ---------------- | ------- | ---------------- | ------------------------------------ | --------------------------------------- |
| `bind`           | string  | `127.0.0.1`      | `127.0.0.1`                          | Address that the SNMP engines listen on |
| `port_base`      | integer | `16101`          | 1024 to 65280                        | UDP port of the root device             |
| `profile`        | string  | `asuswrt-merlin` | lower-case name, up to 32 characters | MIB profile that renders the answers    |
| `community_file` | path    | none             | file name or path                    | File that holds the SNMP v2c community  |

- `bind`: the proxy serves SNMP on the loopback address only. Any other value is an error.
- `profile`: `asuswrt-merlin` is the only profile. Any other name passes `check-config`, but then no
  node gets an engine and `run` logs `no engine: unknown profile`.
- `community_file`: use a long random string. `openssl rand -hex 16` makes one.

```toml
[snmp]
bind = "127.0.0.1"
port_base = 16101
profile = "asuswrt-merlin"
community_file = "snmp_community"
```

### SNMP ports

Each served device gets its own SNMP engine on its own UDP port.

- The root device serves `port_base`.
- The node at position N of `nodes.expected` serves `port_base + N`.
- A node that is not in `nodes.expected` takes the next free index above the reserved ones.
- `ports.json` pins each node MAC to its index for good. A node that disappears or changes its IP
  never moves the port of another node.
- `override.port` pins a node to a port you choose. A node that held that index moves to the next
  free one.
- The index is at most 255, so a service uses ports `port_base` to `port_base + 255` at most.
- Each service on one host needs its own `port_base`. See [Instances](#instances).

## `[snmp.v3]`

Optional SNMPv3 with authentication and privacy (authPriv). Use it beside the v2c community or
instead of it. All keys sit in one `[snmp.v3]` table.

| Key             | Type   | Default        | Allowed values                                      | Purpose                                       |
| --------------- | ------ | -------------- | --------------------------------------------------- | --------------------------------------------- |
| `user`          | string | none, required | 1 to 32 characters from `A-Za-z0-9._-`              | The SNMPv3 user name                          |
| `auth`          | string | `SHA-256`      | `SHA-1`, `SHA-224`, `SHA-256`, `SHA-384`, `SHA-512` | Authentication protocol                       |
| `auth_key_file` | path   | none, required | file name or path                                   | File that holds the authentication passphrase |
| `priv`          | string | `AES-128`      | `AES-128`                                           | Privacy protocol                              |
| `priv_key_file` | path   | none, required | file name or path                                   | File that holds the privacy passphrase        |

- Each passphrase has at least 8 characters.
- `auth` and `priv` ignore case: `sha-256` works.
- The unit loads only the files that the default config names. Add a `LoadCredential=` line for each
  v3 key file in a drop-in. See [Secret files](#secret-files).
- `onboard` adds v2c devices only. It needs `community_file`, even when v3 is on.

```toml
[snmp.v3]
user = "librenms"
auth = "SHA-256"
auth_key_file = "snmp_auth_key"
priv = "AES-128"
priv_key_file = "snmp_priv_key"
```

## `[collector]`

How the proxy polls the router.

| Key                   | Type   | Default     | Allowed values                            | Purpose                                              |
| --------------------- | ------ | ----------- | ----------------------------------------- | ---------------------------------------------------- |
| `mode`                | string | `root_only` | `root_only`, `per_node`                   | Which devices the proxy logs in to                   |
| `stale_after_s`       | number | `180`       | above 0; above `metrics_interval_s` × 1.1 | Age after which a node's data is never served        |
| `metrics_interval_s`  | number | `60`        | above 0                                   | Seconds between polls of metrics, clients, and ports |
| `topology_interval_s` | number | `300`       | above 0                                   | Seconds between reads of the node list and detail    |
| `request_timeout_s`   | number | `10`        | above 0                                   | Timeout of one router request, in seconds            |

- The proxy adds up to 10 percent of jitter to each interval.
- `stale_after_s`: when a node's newest data is older than this, the node stops answering SNMP.
  LibreNMS then sees the device as down. The proxy never serves old data as if it were new. The
  same limit caps the gap that one counter sample may cover. See
  [Counter sources](metrics.md#counter-sources).
- `metrics_interval_s`: also the interval of the client list and the Ethernet port status.
- `topology_interval_s`: also the interval of the device detail: uptime, CPU cores, RAM, temperatures,
  and channels.

Modes:

| Mode        | Router logins                 | What it adds                                                                                                           |
| ----------- | ----------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `root_only` | one, to the root device       | What the root reports for each node: model, firmware, radios, clients, backhaul, traffic rates, CPU and memory percent |
| `per_node`  | one more for each AiMesh node | For each node: uptime, temperatures, CPU cores, RAM size, channels, and exact traffic counters                         |

- A `per_node` session needs a pinned node certificate: `asus.node_ca_file`, or `ca_file` in the
  node's `[[override]]`. A node without a pin gets no session, and the proxy logs one warning for
  it.
- Each login target has its own budget of 6 logins in one hour. A router refusal on a node turns
  `per_node` off for that node for 24 hours.
- A standalone router, access point, or media bridge has no nodes. It reports its own detail in
  either mode. Use `root_only`.

```toml
[collector]
mode = "root_only"
stale_after_s = 180
metrics_interval_s = 60
topology_interval_s = 300
request_timeout_s = 10
```

## `[logging]`

| Key     | Type   | Default | Allowed values                                  | Purpose       |
| ------- | ------ | ------- | ----------------------------------------------- | ------------- |
| `level` | string | `INFO`  | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` | Log threshold |

The proxy writes one JSON object per line to standard error. Under systemd the journal keeps them.
A filter masks secret values, tokens, and the device half of every MAC address. The case of the value
does not matter: `info` works.

```toml
[logging]
level = "INFO"
```

## `[onboard]`

Only the `onboard` command reads this table. The `run` command ignores it. See
[Command line](cli.md#onboard).

| Key          | Type   | Default            | Allowed values              | Purpose                                |
| ------------ | ------ | ------------------ | --------------------------- | -------------------------------------- |
| `url`        | string | `http://127.0.0.1` | `http://` or `https://` URL | Base URL of LibreNMS                   |
| `token_file` | path   | none               | file name or path           | File that holds the LibreNMS API token |
| `ca_file`    | path   | none               | PEM file                    | Pins the LibreNMS HTTPS certificate    |
| `hostname`   | string | `sysname`          | `sysname`, `ip`             | How LibreNMS names each device         |

- `url` holds no user name, password, query, or fragment. It must use `https://`, unless you pass
  `--allow-http` to `onboard`. Plain HTTP sends the token in cleartext.
- `token_file` is required when you run `onboard`. Use a token that can only create devices, and
  delete the token after use.
- `ca_file`: with it, `onboard` trusts that certificate and no other for LibreNMS. Without it,
  `onboard` uses the system trust store.
- `hostname = "sysname"` names each device by the sysName that the proxy serves. `"ip"` names it by
  the LAN IP of the node. See [Overrides](#override) for how the proxy picks the sysName.

```toml
[onboard]
url = "https://192.168.50.10"
token_file = "librenms_token"
ca_file = "librenms.pem"
hostname = "sysname"
```

## `[[override]]`

An override changes one node. Write one `[[override]]` table for each node, and none for the nodes
you leave as they are. Environment variables cannot set overrides.

| Key        | Type    | Default        | Allowed values                         | Purpose                                             |
| ---------- | ------- | -------------- | -------------------------------------- | --------------------------------------------------- |
| `match`    | string  | none, required | IPv4 address or MAC address            | The node to change                                  |
| `sys_name` | string  | derived        | 1 to 63 characters from `A-Za-z0-9._-` | Name that the node serves as sysName                |
| `port`     | integer | derived        | `port_base` + 1 to `port_base` + 255   | Pins the node to one SNMP port                      |
| `login`    | boolean | `true`         | `true`, `false`                        | `false` skips the `per_node` login for this node    |
| `location` | string  | none           | up to 255 characters                   | The sysLocation that the node serves                |
| `exclude`  | boolean | `false`        | `true`, `false`                        | `true` leaves the node out; no other key may follow |
| `ca_file`  | path    | none           | PEM file                               | The node's own certificate, for `per_node`          |

- `match`: a MAC address survives a change of DHCP lease; an IP address does not. A MAC matches
  with colons, hyphens, or no separator. The MAC match wins over an IP match.
- Names: the root is `aimesh-root`. Another node is `aimesh-` plus the last six hex digits of its
  MAC. When two names clash, the proxy uses `aimesh-` plus the full MAC. Only the root may use
  `aimesh-root`. Two overrides never share a `match`, a `sys_name` (ignoring case), or a `port`.
- `port`: a second node cannot take a port that another node holds until you restart the service.
- `exclude`: an excluded node gets no engine and no port. It takes no other key.
- `ca_file`: pins the node's own certificate, and only that exact certificate, whatever name it
  carries. Create the file with `discover --pin-cert PATH --node MAC|IP`. It cannot combine with
  `login = false`.
- To name a standalone device, match its `asus.host` address.

```toml
[[override]]
match = "192.168.50.12"        # or a MAC: "00:00:5e:00:53:12"
sys_name = "aimesh-example"
port = 16150
login = true
location = "Second floor"
ca_file = "node-12.pem"

[[override]]
match = "00:00:5e:00:53:13"
exclude = true
```

## Secret files

A secret never goes into the config. Each secret sits in a file, and a key names that file.

| Key                     | File name in the example | Content                              | Created by                     |
| ----------------------- | ------------------------ | ------------------------------------ | ------------------------------ |
| `asus.password_file`    | `asus_password`          | The router admin password            | You                            |
| `snmp.community_file`   | `snmp_community`         | The SNMP v2c community               | You                            |
| `snmp.v3.auth_key_file` | `snmp_auth_key`          | The SNMPv3 authentication passphrase | You                            |
| `snmp.v3.priv_key_file` | `snmp_priv_key`          | The SNMPv3 privacy passphrase        | You                            |
| `onboard.token_file`    | `librenms_token`         | The LibreNMS API token               | You; delete it after `onboard` |

A secret file must meet these rules. The proxy checks them at start and in `check-config`.

- It is a regular file. The service user or root owns it.
- Group and others have no access. Use mode `0600`. A POSIX ACL counts too.
- It holds one line of UTF-8 text, at most 4096 bytes. A trailing newline is fine. An empty file is
  an error.
- An SNMPv3 passphrase has at least 8 characters.

Certificate files hold public data. They are not secret, but they must not be writable by group or
others (mode `0644`), and they hold PEM text only:

| Key                 | File name in the example | Content                         | Created by                                |
| ------------------- | ------------------------ | ------------------------------- | ----------------------------------------- |
| `asus.ca_file`      | `asus_router.pem`        | The router certificate          | `discover --pin-cert PATH`                |
| `asus.node_ca_file` | `asus_node_ca.pem`       | The CA of the node certificates | `discover --pin-node-ca PATH`             |
| `override.ca_file`  | `node-12.pem`            | One node's own certificate      | `discover --pin-cert PATH --node ADDRESS` |
| `onboard.ca_file`   | `librenms.pem`           | The LibreNMS certificate        | You                                       |

`ADDRESS` is the MAC or the IPv4 address of the node.

If a file is missing, the error names the key and the folder, and says what the value must be:

```text
config error: asus.password_file: file not found in /etc/aimesh-snmp-proxy; the value must name a file such as asus_password, not the secret itself
```

The message never prints the value you typed, because it may be the secret.

Under the systemd unit, `install.sh` creates the folder `/etc/aimesh-snmp-proxy` (mode `0700`) with
empty placeholder files for the password, the community, and the router certificate. The unit copies
these files into a private credentials folder at start. A file outside the default names needs a
`LoadCredential=` line in a drop-in; run `systemctl edit aimesh-snmp-proxy` and add, for SNMPv3:

```ini
[Service]
LoadCredential=snmp_auth_key:/etc/aimesh-snmp-proxy/snmp_auth_key
LoadCredential=snmp_priv_key:/etc/aimesh-snmp-proxy/snmp_priv_key
```

`install.sh` adds the credentials for `asus.node_ca_file` and each `override.ca_file` itself. Run it
again after you add one. The `[onboard]` files are not credentials: you run `onboard` by hand, and it
reads them from the folder of the config file. See [Installation](../installation.md).

Keep the relative file names. The service user cannot read the folder `/etc/aimesh-snmp-proxy`, so an
absolute path into it fails under the unit. The unit reads a relative name from its credentials
folder.

## Environment variables

| Variable                         | Effect                                                         |
| -------------------------------- | -------------------------------------------------------------- |
| `AIMESH_PROXY_CONFIG`            | Path of the config file for the command line. `-c` wins.       |
| `AIMESH_PROXY__<SECTION>__<KEY>` | Overrides one key. Two underscores split the parts.            |
| `CREDENTIALS_DIRECTORY`          | Set by systemd. Relative `*_file` paths resolve here.          |
| `STATE_DIRECTORY`                | Set by systemd. Its first entry is the default of `state_dir`. |

For `AIMESH_PROXY__<SECTION>__<KEY>`, write the names in upper case. Use `STATE_DIR` for the top-level
key and `SNMP__V3__USER` for a key of `[snmp.v3]`:

```sh
AIMESH_PROXY__COLLECTOR__MODE=per_node
AIMESH_PROXY__LOGGING__LEVEL=DEBUG
AIMESH_PROXY__STATE_DIR=/srv/aimesh-state
AIMESH_PROXY__NODES__EXPECTED="192.168.50.11-14,192.168.50.20"
```

- A boolean accepts `1`, `true`, `yes`, `on`, `0`, `false`, `no`, and `off`.
- A list takes comma-separated items.
- The environment cannot carry a secret. `AIMESH_PROXY__ASUS__PASSWORD` fails with
  `inline secrets are not allowed; use password_file`. Name a file with
  `AIMESH_PROXY__ASUS__PASSWORD_FILE`.
- An error names the variable: `asus.port (from $AIMESH_PROXY__ASUS__PORT): expected an integer`.

## State files

The proxy writes these files to `state_dir`. Keep the folder when you upgrade.

| File                         | Written by        | Content                                                                                                    |
| ---------------------------- | ----------------- | ---------------------------------------------------------------------------------------------------------- |
| `ports.json`                 | `run`             | The SNMP port index of each node MAC. LibreNMS devices point at these ports.                               |
| `counters.json`              | `run`             | The derived octet counters, so they never go backwards. Saved every 60 seconds.                            |
| `lockout.json`               | `run`             | The router login budget, backoff, and latches. It holds a salted hash of the password, never the password. |
| `onboarded.json`             | `onboard --apply` | The LibreNMS devices that `onboard` created. `onboard --remove` deletes only these.                        |
| `__pysnmp/<engine id>/boots` | `run`             | The SNMPv3 boot counter of each node engine                                                                |

- Each write goes to a temp file first, then replaces the old file. A crash leaves the old file or
  the new one, never half of one. State files get mode `0600`.
- `ports.json` is JSON: `{"version": 1, "next_index": 3, "nodes": {"00:00:5e:00:53:11": 1}}`. If it
  is damaged, the proxy refuses to start and prints a `state error:` line. A node outside
  `nodes.expected` may get a new port after you move the file aside.
- `lockout.json` holds a router refusal across restarts. Fix the cause, then send SIGHUP to clear
  the latch. A latch for bad credentials clears itself when the password changes. Restart the
  service after you edit the password file, because the unit holds a copy of it. See
  [Troubleshooting](../troubleshooting.md).

## Instances

One service logs in to one root device. For a second device, a standalone router, access point, or
media bridge, run another service. The installer makes it from the template unit
`aimesh-snmp-proxy@NAME`.

| Item               | Single service               | Instance `NAME`                   |
| ------------------ | ---------------------------- | --------------------------------- |
| Unit               | `aimesh-snmp-proxy`          | `aimesh-snmp-proxy@NAME`          |
| Install            | `install.sh`                 | `install.sh --instance NAME`      |
| Config folder      | `/etc/aimesh-snmp-proxy/`    | `/etc/aimesh-snmp-proxy/NAME/`    |
| State folder       | `/var/lib/aimesh-snmp-proxy` | `/var/lib/aimesh-snmp-proxy-NAME` |
| Journal identifier | `aimesh-snmp-proxy`          | `aimesh-snmp-proxy-NAME`          |

- `NAME` has 1 to 32 characters: lower-case letters, digits, and `-`, not at either end. An instance
  needs systemd 247 or newer.
- The config file, the secret files, and the pins keep their usual names. They sit in the folder of
  the instance.
- Every service needs its own `snmp.port_base`: 16101, 16201, 16301, and so on. The installer
  refuses a `port_base` that another service on the host already uses.
- An instance needs its own `state_dir`. The installer writes the right path into its first config.
- Name each standalone device with an `[[override]]` that matches its `asus.host`. Without it, both
  services serve `aimesh-root`, and `onboard` treats the second one as already added.
- Pass the config path to every command with `-c`.

Run a command for an instance with its own config path:

```sh
sudo /opt/aimesh-snmp-proxy/venv/bin/aimesh-snmp-proxy \
  -c /etc/aimesh-snmp-proxy/NAME/config.toml check-config
```

This config belongs to an access point in an instance called `second-ap`:

```toml
# /etc/aimesh-snmp-proxy/second-ap/config.toml
state_dir = "/var/lib/aimesh-snmp-proxy-second-ap"

[asus]
host = "192.168.50.2"
username = "admin"
password_file = "asus_password"
ca_file = "asus_router.pem"

[snmp]
port_base = 16201
community_file = "snmp_community"

[[override]]
match = "192.168.50.2"
sys_name = "aimesh-second-ap"
```

See [Multiple routers](../instances.md) for the full steps.

## Error messages

`check-config` prints these, and `run` logs them. All config errors exit with code 78.

| Message starts with                                                            | Cause                                                    | Fix                                                     |
| ------------------------------------------------------------------------------ | -------------------------------------------------------- | ------------------------------------------------------- |
| `config file not found: <path>`                                                | The path is wrong                                        | Pass `-c`, or set `AIMESH_PROXY_CONFIG`                 |
| `invalid TOML in <path>: ...`                                                  | A syntax error                                           | Fix the line that the message names                     |
| `<key>: unknown key`                                                           | The key is not in this reference                         | Fix the spelling, or remove the key                     |
| `<key>: inline secrets are not allowed; use <key>_file`                        | A secret value sits in the file or in the environment    | Put it in a file, and name the file                     |
| `<key>: required`                                                              | A required key is missing                                | Add the key                                             |
| `asus.use_ssl: must be true; ...`                                              | `use_ssl = false`                                        | Remove the key, or set `true`                           |
| `snmp.bind: must be 127.0.0.1: ...`                                            | Another bind address                                     | Use `127.0.0.1`                                         |
| `snmp.port_base: must be between 1024 and 65280`                               | The port base is out of range                            | Pick a port in the range                                |
| `snmp: set community_file (v2c) or add [snmp.v3]`                              | No SNMP credentials                                      | Add `community_file` or `[snmp.v3]`                     |
| `collector.stale_after_s: must exceed metrics_interval_s plus 10% jitter, ...` | `stale_after_s` is at most `metrics_interval_s` × 1.1    | Raise `stale_after_s`                                   |
| `nodes.expected: expected IPv4 addresses or ranges like ...`                   | A bad address or range                                   | Use `192.168.50.11` or `192.168.50.11-19`               |
| `nodes.expected: lists an address twice`                                       | Two items overlap                                        | Remove the duplicate                                    |
| `override[N]: duplicate match (same as override[M])`                           | Two overrides share a `match`, a `sys_name`, or a `port` | Merge them                                              |
| `override[N]: an excluded node takes no other settings`                        | `exclude = true` beside other keys                       | Keep only `match` and `exclude`                         |
| `override[N].port: must be between ... and ...`                                | The port is outside `port_base` + 1 to `port_base` + 255 | Pick a port in the range                                |
| `<key>: file not found in <folder>; ...`                                       | A secret or certificate file is missing                  | Create it, in the folder that `*_file` resolves against |
| `<key>: ... is accessible to group or others (mode 0644); run chmod 600`       | A secret file is too open                                | `chmod 600` the file                                    |
| `<key>: ... is writable by group or others (mode 0664); run chmod 644`         | A certificate file is too open                           | `chmod 644` the file                                    |
| `asus.ca_file: ... contains a private key; export the certificate only`        | The pin file holds a key                                 | Export the certificate alone                            |
| `state error: <path>: ...`                                                     | `ports.json` is damaged                                  | Fix it, or move it aside                                |
| `$AIMESH_PROXY__...: expected AIMESH_PROXY__<SECTION>__<KEY>`                  | A bad environment variable name                          | Use a section and a key                                 |
| `refusing to run as root (uid 0); ...`                                         | `run` started as root or as `librenms`                   | Start it through the service unit                       |
