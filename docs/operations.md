# Operations

Day-to-day tasks for a running service. Commands use the single service `aimesh-snmp-proxy`. For an
[instance](instances.md), use `aimesh-snmp-proxy@NAME` as the unit name and
`/etc/aimesh-snmp-proxy/NAME/config.toml` as the config file.

```sh
APP=/opt/aimesh-snmp-proxy/venv/bin/aimesh-snmp-proxy
```

## Start, stop, and check

```sh
sudo systemctl enable --now aimesh-snmp-proxy
sudo systemctl status aimesh-snmp-proxy
sudo systemctl restart aimesh-snmp-proxy
sudo systemctl stop aimesh-snmp-proxy
```

Each start logs in once to every device the proxy logs in to, and a stop logs out. The router
limits logins, so the proxy keeps a budget of 6 logins per hour for each of those devices. Avoid a
loop of restarts. The unit stops after 5 failed starts in 15 minutes to protect the router.

After a start or restart, wait 6 minutes before you run a LibreNMS discovery. Wait 11 minutes in
`per_node` mode. See [Wait before you run discovery](librenms.md#wait-before-you-run-discovery).

Use the router web UI as little as you can while the service runs. A login from your browser
clashes with the proxy session. The router can then refuse the proxy login. The proxy waits 2 to 5
minutes and tries again.

## Read the logs

```sh
sudo journalctl -u aimesh-snmp-proxy -e
sudo journalctl -u aimesh-snmp-proxy -f
```

The service writes one JSON object per line. The `msg` field says what happened. The log shows
each device once when it starts or stops answering:

```json
{"ts": "2026-11-15T18:30:12.411Z", "level": "INFO", "logger": "aimesh_snmp_proxy.ops.run", "msg": "node aimesh-root (00:00:5e:**:**:**): engine on 127.0.0.1:16101"}
{"ts": "2026-11-15T18:30:20.002Z", "level": "INFO", "logger": "aimesh_snmp_proxy.collector.store", "msg": "node aimesh-root (00:00:5e:**:**:**): SERVING"}
{"ts": "2026-11-15T19:02:45.870Z", "level": "INFO", "logger": "aimesh_snmp_proxy.collector.store", "msg": "node aimesh-005311 (00:00:5e:**:**:**): SILENT, stale (older than 180 s)"}
```

A filter masks secrets in every record, and it masks the device half of each MAC address. IP addresses
stay. Remove them before you post a log in a public issue. Set `[logging] level = "DEBUG"` for more
detail.

## Change the configuration

1. Stop the service: `sudo systemctl stop aimesh-snmp-proxy`.
2. Edit `/etc/aimesh-snmp-proxy/config.toml`.
3. If you changed `asus.host`, `nodes.expected`, `collector.mode`, or a node pin, run
   `sudo ./deploy/install.sh` from the bundle folder. The installer rebuilds the address allow list
   in the unit.
4. Check the file: `sudo $APP check-config`.
5. Start the service.

For a change to any other key, or to a secret file, restart the service. It reads copies of the
files made at start.

Never edit the unit file. The installer overwrites it. Put local changes in a drop-in:

```sh
sudo systemctl edit aimesh-snmp-proxy
```

## Upgrade

The installer keeps the config, the secrets, and the state. It rebuilds the shared environment and
restores the old one if the build fails.

**1. Download and verify the new bundle.** See [Installation](installation.md).

**2. Stop every service.**

```sh
sudo systemctl stop 'aimesh-snmp-proxy*'
```

**3. Unpack the bundle and run the installer from its folder.**

```sh
sudo tar -xzf aimesh-snmp-proxy-NEW.tar.gz -C /usr/local/src
cd /usr/local/src/aimesh-snmp-proxy-NEW
sudo ./deploy/install.sh
```

**4. Compare your config with the new example.** The installer prints the path:
`diff /etc/aimesh-snmp-proxy/config.toml config.example.toml`. Read the [changelog](changelog.md) for
new keys.

**5. Check and start.** Start each instance too.

```sh
sudo $APP check-config
sudo systemctl start aimesh-snmp-proxy
```

All services share one environment and one unit template. Run the installer once without
`--instance` to upgrade them all. On a host that has instances only, run
`sudo ./deploy/install.sh --instance NAME` for one instance instead.

## Roll back

Keep the old bundle folders in `/usr/local/src`. To go back:

1. Stop every service: `sudo systemctl stop 'aimesh-snmp-proxy*'`.
2. Run `sudo ./deploy/install.sh` from the old bundle folder.
3. Start the services.

The state files carry a format version. `ports.json` and `onboarded.json` fail closed: an older
service refuses a newer format and leaves the file untouched. `lockout.json` and `counters.json`
start empty when the format is unknown, and the service overwrites them. Then it forgets the login
budget, and the octet counters restart. Read the changelog before you roll back across a release
that changes a state file.

## Rotate secrets

Rotate every secret once a year and after any exposure. Write each new value with a command that
does not echo it and leaves it out of your shell history.

**Router password.** Stop the service first. A running service would try the old password
against the router and latch. Change the password on the router. Then write the file and start:

```sh
sudo systemctl stop aimesh-snmp-proxy
sudo bash -c 'umask 077; read -rsp "router password: " p; echo
  printf %s "$p" >"$0"' /etc/aimesh-snmp-proxy/asus_password
sudo systemctl start aimesh-snmp-proxy
```

**SNMP community.** Write a new random value, restart, and update each LibreNMS device. See
[Change the community of existing devices](librenms.md#change-the-community-of-existing-devices).

```sh
sudo sh -c 'umask 077; openssl rand -hex 16 >"$0"' /etc/aimesh-snmp-proxy/snmp_community
sudo systemctl restart aimesh-snmp-proxy
```

**LibreNMS token.** Revoke it in LibreNMS right after `onboard`. Create a new one when you need it.

## Back up and restore

The state folder holds `ports.json`. It ties each node MAC to its SNMP port. Without it, a new
install can give the LibreNMS devices other ports. Back up the config and the state together. They
hold secrets, so keep the archive private.

```sh
sudo sh -c 'umask 077; tar -czf /root/aimesh-backup.tar.gz /etc/aimesh-snmp-proxy /var/lib/private/aimesh-snmp-proxy*'
```

The path `/var/lib/private/aimesh-snmp-proxy*` is where systemd keeps the state of a service with
`DynamicUser=`. On the legacy static-user variant, the state is in `/var/lib/aimesh-snmp-proxy`
itself. To restore, stop the services, unpack at the root, and start them:

```sh
sudo tar -xzf /root/aimesh-backup.tar.gz -C /
```

## Clear a login latch

The proxy stops logging in to the router after it refuses the credentials, asks for a CAPTCHA, or
asks for a password reset. The latch survives restarts. Fix the cause on the router. Then tell the
service to clear the latch and the backoff:

```sh
sudo systemctl kill -s HUP aimesh-snmp-proxy
```

See [Troubleshooting](troubleshooting.md#the-log-says-latched).

## Uninstall

**1. Optional: delete the LibreNMS devices that `onboard` created.** This needs a new API token and
the `[onboard]` table. See [Remove the devices](librenms.md#remove-the-devices).

```sh
sudo $APP onboard --remove --apply
```

**2. Remove each instance first.** The single service owns the shared environment, so the installer
refuses to remove it while instances remain.

```sh
sudo ./deploy/install.sh --instance NAME --uninstall
```

**3. Remove the single service.** This stops it and removes the unit, the unit template, and the
environment. It keeps `/etc/aimesh-snmp-proxy` and the state.

```sh
sudo ./deploy/install.sh --uninstall
```

**4. Optional: delete the config and the state too.** Add `--purge`. The command asks you to type
`purge`. Pass `--yes` to skip that. The state holds the port pins, so a later install may give your
devices other ports.

```sh
sudo ./deploy/install.sh --uninstall --purge
```

Use `--dry-run` with any of these commands to see the plan first.
