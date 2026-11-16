# aimesh-snmp-proxy

Serves a stock-firmware ASUS router over SNMP so LibreNMS shows each AiMesh node,
or a standalone router, access point or media bridge (one root node), as its own
wireless device. It reads the router's HTTPS web API (read-only, allowlisted) and
answers SNMP v2c on `127.0.0.1` only, one port per device, natively under systemd
on the LibreNMS host as a throwaway `DynamicUser`: never root, never `librenms`.

## Requirements

- Host: Linux with systemd 247+, Python 3.11+ and a native LibreNMS in
  `/opt/librenms`; on Debian or Ubuntu `apt install python3-venv` first.
- Router: HTTPS admin login (ASUS Administration > System > Authentication
  Method: HTTPS or Both). Port 8443 by default; `asus.port` changes it. The
  examples use the router `192.168.50.1` and the LibreNMS host `192.168.50.10`.

## Install

On a dev machine (`uv`, `git`), `make bundle` runs `deploy/build-bundle.sh`: the
wheel, an `asusrouter` wheel and the `uv export` lock, all hash-pinned, go into
`dist/aimesh-snmp-proxy-<version>.tar.gz` and a `.sha256`. The host needs PyPI:

```sh
V=0.3.0 # the version you built
scp dist/aimesh-snmp-proxy-$V.tar.gz* 192.168.50.10:/tmp/
cd /tmp && sha256sum -c aimesh-snmp-proxy-$V.tar.gz.sha256
sudo tar -xzf aimesh-snmp-proxy-$V.tar.gz -C /usr/local/src
cd /usr/local/src/aimesh-snmp-proxy-$V
sudo ./deploy/install.sh --dry-run   # checks only; --python PATH picks one
sudo ./deploy/install.sh             # never starts or enables the service
```

Fill the secrets (no echo, nothing in argv or history), edit the config
(`asus.host` must be an IP; re-run `install.sh` after changing it), pin the
router certificate (compare its fingerprint with the router's), and test with
the service stopped: a second router login clashes with its session. Then start:

```sh
sudo bash -c 'umask 077; read -rsp "router password: " p; echo
  printf %s "$p" >"$0"' /etc/aimesh-snmp-proxy/asus_password
sudo sh -c 'umask 077; openssl rand -hex 16 >"$0"' \
  /etc/aimesh-snmp-proxy/snmp_community
sudo ${EDITOR:-nano} /etc/aimesh-snmp-proxy/config.toml
APP=/opt/aimesh-snmp-proxy/venv/bin/aimesh-snmp-proxy
sudo $APP discover --pin-cert /etc/aimesh-snmp-proxy/asus_router.pem
sudo $APP discover --pin-node-ca /etc/aimesh-snmp-proxy/asus_node_ca.pem
sudo $APP check-config && sudo $APP selftest
sudo systemctl enable --now aimesh-snmp-proxy
systemd-analyze verify /etc/systemd/system/aimesh-snmp-proxy.service
systemd-analyze security aimesh-snmp-proxy
```

Per-node uptime, temperature, cores and RAM: `collector.mode = "per_node"`, all
node IPs in `nodes.expected`, `asus.node_ca_file` from `--pin-node-ca` (a node's
chain, else the root's `/cert.crt` if it issued both pins) or a node's `ca_file`
in its `[[override]]` from `--pin-cert PATH --node MAC`; re-run `install.sh`.

## Instances, upgrade, uninstall

Each further router (an AiMesh root, or a standalone router, AP or media bridge)
gets an instance: unit `aimesh-snmp-proxy@NAME`, config
`/etc/aimesh-snmp-proxy/NAME/`, state `/var/lib/aimesh-snmp-proxy-NAME`. Each
needs its own `snmp.port_base` (16201, 16301, ...): the installer refuses a
shared one. Secrets, certificate pin, and `onboard` work as above, in that
folder.

```sh
sudo ./deploy/install.sh --instance bridge   # a-z 0-9 -; needs systemd 247+
sudo $APP -c /etc/aimesh-snmp-proxy/bridge/config.toml selftest
sudo systemctl enable --now aimesh-snmp-proxy@bridge
```

All services share the venv. Upgrade: stop them all
(`sudo systemctl stop 'aimesh-snmp-proxy*'`), unpack the new bundle, run
`sudo ./deploy/install.sh`, start them. The installer refuses while any runs,
rebuilds the venv (restoring the old one on failure), and keeps config,
secrets, state. `install.sh --uninstall` removes the unit and venv, but not
while instances remain: run `install.sh --instance NAME --uninstall` first.
`--purge` also deletes the config and state, which holds the SNMP port pins: a
re-install may then give devices other ports.

## Onboard into LibreNMS

The service must run first: it pins one SNMP port per node in `ports.json`.
Make an API token for a user that may only create devices (no `unmask`). Use
HTTPS: nginx redirects :80 and `onboard` refuses cross-origin redirects. If the
system store does not trust the LibreNMS certificate, pin it and compare its
fingerprint with the browser's:

```sh
openssl s_client -connect 192.168.50.10:443 -servername 192.168.50.10 \
  </dev/null 2>/dev/null |
  sudo openssl x509 -out /etc/aimesh-snmp-proxy/librenms.pem
sudo openssl x509 -in /etc/aimesh-snmp-proxy/librenms.pem -noout \
  -fingerprint -sha256
sudo bash -c 'umask 077; read -rsp "API token: " t; echo
  printf %s "$t" >"$0"' /etc/aimesh-snmp-proxy/librenms_token
```

In `config.toml` uncomment `[onboard]`: `url = "https://192.168.50.10"`,
`token_file = "librenms_token"`, and `ca_file = "librenms.pem"` if you pinned;
a pinned self-signed certificate (CN=IP, no SAN) works. Plain HTTP on loopback
only: `url = "http://127.0.0.1"` plus `--allow-http` on each `onboard` command.
`hostname = "ip"` names each device by its node's LAN IP, not the sysName it
serves (`"sysname"`, the default). A device already at `127.0.0.1:<port>`,
renamed or not, is left alone; the token's user must be able to see it.

All nodes share `127.0.0.1`: ICMP must be off when LibreNMS creates them (it
reads `icmp_check` only then). Off before `onboard`, on after:

```sh
sudo -u librenms /opt/librenms/lnms config:set icmp_check false
sudo $APP onboard
sudo $APP onboard --apply
sudo -u librenms /opt/librenms/lnms config:set icmp_check true
```

Then revoke the token and delete `librenms_token` and `librenms.pem`.
Rollback: `onboard --apply --remove` deletes only the devices it created, found
by id so renamed ones go too; then `install.sh --uninstall`.

## Troubleshooting

- Exit 78 is a config error and is not restarted. Read
  `sudo journalctl -u aimesh-snmp-proxy -e`, fix the key, restart. The service
  sees copies of the files taken at start: restart after every edit.
- `243/CREDENTIALS`: a credential file is missing: run `install.sh` again.
- "latched": `/var/lib/aimesh-snmp-proxy/lockout.json` keeps a router refusal
  (bad password, CAPTCHA, reset) across restarts. Fix the cause, then
  `sudo systemctl kill -s HUP aimesh-snmp-proxy`. Last resort: stop the service
  and delete `lockout.json` (this also resets the login budget).
- `start request repeated too quickly` (5 failures in 15 minutes protect the
  router): fix it, then `systemctl reset-failed aimesh-snmp-proxy`.
- Dies at start with an mprotect or SIGSYS error (`status=31/SYS`): the sandbox
  does not fit your Python build. Set `MemoryDenyWriteExecute=no` in a drop-in
  (`systemctl edit aimesh-snmp-proxy`) and open an issue.

## Security

- Secrets sit in `/etc/aimesh-snmp-proxy` (0700 root, files 0600) and reach the
  service through `LoadCredential=`, never the environment or argv. Optional on
  systemd 250+: `LoadCredentialEncrypted=` (one-shot commands need plain files).
- The router certificate is pinned (no plain-HTTP fallback); installs are
  hash-pinned and binary-only. Rotate secrets yearly and after exposure.
