# Troubleshooting

Find your symptom, read the cause, and apply the fix. Most commands need `sudo`.

```sh
APP=/opt/aimesh-snmp-proxy/venv/bin/aimesh-snmp-proxy
```

The proxy uses these exit codes: `0` for success, `1` for a failed check, `2` for a usage error, and
`78` for a configuration error. Exit 78 means a restart cannot help, so systemd does not restart the
service.

## A config error stops the service

`check-config` and the service print `config error: KEY: PROBLEM`. The message names the key and
never a secret value. Read the journal:

```sh
sudo journalctl -u aimesh-snmp-proxy -e
```

| Message                                                             | Cause                                | Fix                                                      |
| ------------------------------------------------------------------- | ------------------------------------ | -------------------------------------------------------- |
| `KEY: file not found`                                               | A `*_file` key names a missing file  | Create the file, or run `install.sh` again               |
| `... is accessible to group or others (mode 0644)`                  | A secret file is readable by others  | `sudo chmod 600 FILE`                                    |
| `... is owned by uid N; it must belong to the service user or root` | The file has the wrong owner         | `sudo chown root:root FILE`                              |
| `asus.ca_file: PATH holds no PEM certificate`                       | You have not pinned the router yet   | Run `discover --pin-cert`                                |
| `snmp: set community_file (v2c) or add [snmp.v3]`                   | No SNMP credential is set            | Set `snmp.community_file`                                |
| `NAME: unknown key`                                                 | A typo, or a key in the wrong table  | Compare with the [reference](reference/configuration.md) |
| `NAME: inline secrets are not allowed; use NAME_file`               | You put a secret value in the config | Move it to a file and name the file                      |
| `state_dir belongs at the top of the file`                          | `state_dir` sits below a `[section]` | Move it above the first `[section]`                      |

If a message says the value "must name a file", you typed the secret itself into the config. Change
the value to a file name. Treat that secret as exposed and replace it.

## The service does not start

| Symptom                                         | Cause                                                        | Fix                                                                                                                   |
| ----------------------------------------------- | ------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| `status=78` and no restart                      | A config error                                               | Fix the key, then `systemctl start`                                                                                   |
| `243/CREDENTIALS`                               | A file that the unit loads is missing                        | Create the file again. `install.sh` recreates only the empty `asus_password`, `snmp_community`, and `asus_router.pem` |
| `start request repeated too quickly`            | 5 failed starts in 15 minutes. The limit protects the router | Fix the cause, then `sudo systemctl reset-failed aimesh-snmp-proxy`                                                   |
| `status=31/SYS` (SIGSYS) or an `mprotect` error | The sandbox filter is unverified with Python 3.14            | See below                                                                                                             |

For the last row, disable the memory filter in a drop-in and report the problem in an issue:

```sh
sudo systemctl edit aimesh-snmp-proxy
```

```ini
[Service]
MemoryDenyWriteExecute=no
```

## The log says latched

The proxy stops logging in when the router refuses the login in a way that retrying cannot fix. It
stores the latch in `lockout.json`, so a restart does not clear it. Repeated logins would only make
the router lock you out.

| Log message                                          | Cause                       | Fix                                                                                                                                    |
| ---------------------------------------------------- | --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `router refused the credentials`                     | Wrong user name or password | After a new password, restart: the latch clears when the password changes. After you fix only `asus.username`, restart and send SIGHUP |
| `router requires captcha`                            | The router wants a CAPTCHA  | Sign in once in the router web UI, then send SIGHUP                                                                                    |
| `router requires reset_required`                     | The router wants a reset    | Complete the reset on the router, then send SIGHUP                                                                                     |
| `refused (...); per_node off for this node for 24 h` | One node refused its login  | Fix the node pin or the credentials, then send SIGHUP. The hold also ends after 24 hours                                               |

After you fix the cause, clear the latch and the backoff:

```sh
sudo systemctl kill -s HUP aimesh-snmp-proxy
```

As a last resort, stop the service, delete `lockout.json`, and start it again. This also resets
the login budget.

```sh
sudo systemctl stop aimesh-snmp-proxy
sudo rm /var/lib/aimesh-snmp-proxy/lockout.json
sudo systemctl start aimesh-snmp-proxy
```

For a CAPTCHA or a reset latch, the service logs `still latched` and checks once an hour whether
the router is reachable. It never sends credentials during that check.

## The log shows a TLS pin mismatch

```text
TLS pin mismatch: pinned SHA256:..., presented SHA256:...; re-pin only after checking the router out of band
```

The router now presents a different certificate than the one you pinned. A firmware update, a
factory reset, or a certificate renewal can cause this. An attacker on your network can cause it
too.

1. Open the router web UI in a browser. Read the SHA-256 fingerprint of its certificate.
2. Run `discover --pin-cert`. It prints the fingerprint it received. Compare the two.
3. Type `yes` only if they match. Then restart the service, because it reads the pin at start.

```sh
sudo $APP discover --pin-cert /etc/aimesh-snmp-proxy/asus_router.pem
sudo systemctl restart aimesh-snmp-proxy
```

For a node, the message reads `TLS verification failed: node CA ...`. The node certificate must come
from the pinned CA and must name the node IP. Pin again with `discover --pin-node-ca`. If a node has
its own certificate, pin that one with `discover --pin-cert PATH --node MAC` and set `ca_file` in its
`[[override]]`. Then run `install.sh` again so the unit loads the new file.

## `discover` finds no nodes

`discover` prints `no AiMesh nodes read from HOST: OUTCOME (DETAIL)`. The outcome tells you why.

| Outcome          | Meaning                                          | Fix                                                                                         |
| ---------------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| `network`        | No answer, or a transport error                  | Check `asus.host`, `asus.port`, the HTTPS setting, and the firewall                         |
| `pin_mismatch`   | The router certificate differs from the pin      | See the section above                                                                       |
| `credentials`    | Wrong user name or password                      | Correct the file or the user name                                                           |
| `captcha`        | The router requires a CAPTCHA                    | Sign in once in the web UI                                                                  |
| `reset_required` | The router requires a reset                      | Complete it on the router                                                                   |
| `try_again`      | The router locked the login for a while          | Wait. The proxy waits 10 minutes, then longer, up to one hour, or longer if the router asks |
| `another`        | Another admin session is open                    | Close the web UI. The proxy retries after 2 to 5 minutes                                    |
| `unsupported`    | HTTP 404: the router lacks a page the proxy uses | Check the firmware. See the [FAQ](faq.md#which-routers-and-firmware-work)                   |
| `budget`         | The local limit of 6 logins per hour is used     | Wait. Stop restarting the service                                                           |
| `login latched`  | A latch from an earlier run still holds          | See [The log says latched](#the-log-says-latched)                                           |

`pin-cert: cannot fetch the certificate from HOST:PORT` means the TCP or TLS connection failed. Check
that HTTPS login is on and that the port is right.

Run `discover` and `selftest` while the service is stopped. They log in to the router, and a second
login clashes with the proxy session. `check-config` reads files only and never contacts the router.
`discover` also records its login in `lockout.json`, so it counts against the login budget.

## A node is silent

A node that does not answer SNMP is silent on purpose. The log says why:

```text
node NAME (MAC): SILENT, REASON
```

| Reason                                 | Meaning                                                                 |
| -------------------------------------- | ----------------------------------------------------------------------- |
| `absent from the AiMesh list`          | The root no longer lists the node. Check power and the node link        |
| `offline in two AiMesh polls in a row` | The root reports the node offline                                       |
| `no snapshot yet`                      | The service just started. Wait one poll                                 |
| `stale (older than 180 s)`             | No fresh data arrived within `stale_after_s`. Check the root connection |

The proxy never serves old data, because LibreNMS would then show a dead node as alive. LibreNMS
marks the silent node down.

## LibreNMS lost CPU cores or sensors

A discovery that ran during the detail gap after a restart removed them. Wait 6 minutes after the
restart, or 11 minutes in `per_node` mode, then run discovery again:

```sh
sudo -u librenms /opt/librenms/lnms device:discover HOSTNAME
```

See [Wait before you run discovery](librenms.md#wait-before-you-run-discovery).

## One node reports false reboots or 0 degrees

The proxy loses the detail of that node again and again. The cause is usually a bad network link
between the host and the node. Large packets can fail while small ones pass. Test from the host:

```sh
ping -c 20 -s 56 NODE_IP
ping -c 20 -s 1400 -M do NODE_IP
```

If the second command loses packets and the first does not, the link has a fault. Check the cable,
the port, and the switch. The fix is physical. Also read the log for `login budget`. A failing
session uses the 6 logins per hour of that node.

## `onboard` fails

| Message                                                              | Fix                                                                                                                 |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `[onboard] is missing: set url and token_file`                       | Add the `[onboard]` table to `config.toml`                                                                          |
| `[onboard] url uses http://, so the token would travel in cleartext` | Use `https://`, or pass `--allow-http` on the same host                                                             |
| `no ports.json at PATH yet: start the service`                       | A warning only. Start the service to pin node ports. A standalone device never creates the file, so ignore it there |
| `LibreNMS refused a checked add`                                     | Run again with `--force`                                                                                            |
| `onboard stopped: ...` with `HTTP 401` or `HTTP 403`                 | The token is wrong or lacks a right. Create a new token                                                             |
| A TLS error                                                          | Pin the LibreNMS certificate with `[onboard] ca_file`                                                               |

## A port is busy

The log says `retrying, at most every 60 s`, and a node has no engine. Another program holds the
UDP port. Find it with `sudo ss -ulpn | grep PORT`. Free the port, or pick another `snmp.port_base`
and run `install.sh` again. A port belongs to one service only, so the installer refuses a shared
`port_base`.

## Report a problem

Open an issue on [GitHub](https://github.com/islanderman/aimesh-snmp-proxy/issues). Include:

```sh
$APP --version
sudo $APP check-config
systemctl --version | head -n 1
sudo journalctl -u aimesh-snmp-proxy -n 100 --no-pager
```

`check-config` prints no secret values and no MAC addresses. The log masks the device half of each
MAC address but shows IP addresses, so remove those if you want to keep them private. Never post a
password, a community, a token, or a private key.
