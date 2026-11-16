# Multiple routers

One host can serve several routers. Each router gets its own service, called an instance. All
instances share one Python environment and one unit template. Each instance has its own config,
secrets, state, systemd sandbox, and SNMP port range.

Use the single service `aimesh-snmp-proxy` for your first router. Add an instance for each further
router: an AiMesh root with its nodes, a standalone router, an access point, or a media bridge.

## What an instance gets

For an instance named `NAME`:

| Item     | Path or name                                                             |
| -------- | ------------------------------------------------------------------------ |
| Unit     | `aimesh-snmp-proxy@NAME`                                                 |
| Config   | `/etc/aimesh-snmp-proxy/NAME/config.toml`, with its own secrets and pins |
| State    | `/var/lib/aimesh-snmp-proxy-NAME`                                        |
| Drop-ins | `/etc/systemd/system/aimesh-snmp-proxy@NAME.service.d/`                  |
| Logs     | `journalctl -u aimesh-snmp-proxy@NAME`                                   |

`NAME` has 1 to 32 characters: lower-case letters, digits, and `-`. It cannot start or end with `-`.
Instances need systemd 247 or newer.

The installer writes `10-ip-allow.conf` for an instance. It lets the unit reach the router, and the
nodes in `per_node` mode. When the config has node pins, the installer also writes
`20-node-ca.conf`, which loads them. Run the installer again after you change `asus.host`,
`nodes.expected`, `collector.mode`, or a pin.

## Name each router

Every root device serves the name `aimesh-root` by default. `onboard` adds a device only when no
LibreNMS device has its hostname. It finds `aimesh-root` from your first router and skips the root of
the second one with `exists (device N); left unchanged`.

`init --instance NAME` names the root `aimesh-NAME`, so each instance differs from the others. If you
write the config by hand, give each root its own name in one of two ways.

**Add an override.** Its `match` is the router address, and its `sys_name` is unique:

```toml
[[override]]
match = "192.168.50.2"
sys_name = "hall-ap"
```

**Or name the devices by address.** Set `hostname = "ip"` in `[onboard]`. LibreNMS then names each
device by its LAN address. The device still serves its sysName.

Nodes get `aimesh-` plus the last six hex digits of their MAC address, so they differ already.

## Plan the ports

Each service needs its own `snmp.port_base`. A port has one owner, so LibreNMS would poll the wrong
router if two services shared one. The installer refuses a shared base.

| Service             | `snmp.port_base` | Root device | Nodes        |
| ------------------- | ---------------- | ----------- | ------------ |
| `aimesh-snmp-proxy` | `16101`          | 16101       | 16102 and up |
| first instance      | `16201`          | 16201       | 16202 and up |
| second instance     | `16301`          | 16301       | 16302 and up |

Leave 100 ports between bases. A service with more than 99 nodes needs a wider gap.

## Add an instance

**1. Stop the services and install the instance.** Stop every running service, including the one for
your first router. The installer refuses to run while any service runs, even with `--dry-run`. All
services share one environment. Then install the instance. This seeds
`/etc/aimesh-snmp-proxy/ap1/config.toml` from the example and points its `state_dir` at the instance
folder. Use `--dry-run` first.

```sh
cd /usr/local/src/aimesh-snmp-proxy-VERSION
sudo ./deploy/install.sh --instance ap1 --dry-run
sudo ./deploy/install.sh --instance ap1
```

**2. Generate the config for the instance.** `init` reads the configs of your other services and
picks a free block of ports for `snmp.port_base`. It sets `state_dir` to the instance folder, names
the root `aimesh-ap1`, and writes the files into `/etc/aimesh-snmp-proxy/ap1`. `--force` replaces the
files that the installer seeded.

```sh
APP=/opt/aimesh-snmp-proxy/venv/bin/aimesh-snmp-proxy
sudo $APP init --instance ap1 --detect --force
```

To write the files yourself, see [Write the config by hand](onboarding/manual.md). Use the instance
folder and pass `-c` to every command.

**3. Run the installer for the instance again.** The unit reads `asus.host`.

```sh
sudo ./deploy/install.sh --instance ap1
```

**4. Check the config and test.** Pass `-c` so the command reads the instance config. Keep the
service stopped while you test.

```sh
CONF=/etc/aimesh-snmp-proxy/ap1/config.toml
sudo $APP -c $CONF discover
sudo $APP -c $CONF check-config
sudo $APP -c $CONF selftest
```

**5. Start the instance, then start your other services again.**

```sh
sudo systemctl enable --now aimesh-snmp-proxy@ap1
sudo systemctl start aimesh-snmp-proxy
systemd-analyze security aimesh-snmp-proxy@ap1
```

**6. Add its devices to LibreNMS with `onboard`.** Put an `[onboard]` table in the instance config.
The instance keeps its own `onboarded.json`, so `onboard --remove` deletes only that instance's
devices. Turn ICMP off before `--apply` and on after. See [LibreNMS](librenms.md).

```sh
sudo $APP -c $CONF onboard
sudo $APP -c $CONF onboard --apply
```

## Upgrade and remove instances

All services share one environment. Stop every service before you upgrade. The installer refuses to
run while any service runs. See [Operations](operations.md#upgrade).

To remove one instance, run `sudo ./deploy/install.sh --instance ap1 --uninstall`. It removes the
drop-ins and keeps the config and the state. Add `--purge` to delete them. The shared environment
stays. See [Uninstall](operations.md#uninstall) for the order.
