# Standalone router

This guide serves a router that runs alone in router mode, with no AiMesh nodes. LibreNMS gets
one device. See [Choose your path](index.md) for the overview.

## 1. Prepare the device

1. Open the router web UI. Go to _Administration_, then _System_. Set _Authentication Method_ to
   `HTTPS` or `Both`. Note the HTTPS port. The default is 8443.
2. Reserve a fixed address for the router on your DHCP server, or set a static address.
3. Note the LAN address of the router, for example `192.168.50.1`.

## 2. Install the service

Follow [Installation](../installation.md). It leaves the service installed but not started. Stop
every service that polls this device.

## 3. Generate the config

```sh
APP=/opt/aimesh-snmp-proxy/venv/bin/aimesh-snmp-proxy
sudo $APP init --detect
```

`init` asks a few questions. Each shows its default in brackets, and Enter takes it. The questions
are the instance name (leave it empty), the router address, the HTTPS port, the admin user, the
router type (`auto` is right), the name that LibreNMS shows, the SNMP port base, and the LibreNMS
address (optional). It asks for the admin password last, and the prompt does not echo. See
[`init`](../reference/cli.md#init) for every flag.

Answer the name question with a name of your own, for example `home-router`. The default
`aimesh-root` clashes in LibreNMS when you serve a second router.

With `--detect`, `init` then fetches the certificate of the device and prints its SHA-256
fingerprint. Compare it with the one your browser shows for `https://192.168.50.1:8443`. Type `yes` only if
they match. `init` logs in once and finds out that the device has no AiMesh nodes:

```text
detected: a standalone router, AP or media bridge
  root  192.168.50.1  RT-EXAMPLE  online
```

It writes `config.toml`, `asus_password`, a random `snmp_community`, and `asus_router.pem` into
`/etc/aimesh-snmp-proxy`. It replaces the `config.toml` and the empty files that the installer
seeded. It replaces an edited config or a filled secret file only with `--force`, and a forced run
makes a new SNMP community. It prints the next steps.

To answer with flags instead, pass `--host`. To write the files yourself, see
[Write the config by hand](manual.md).

## 4. Run the installer again

The unit reads `asus.host`. Run the installer again from the bundle folder, so the unit can reach the
address you gave. Stop every service first.

```sh
cd /usr/local/src/aimesh-snmp-proxy-VERSION
sudo ./deploy/install.sh
```

## 5. Check

Keep the service stopped while you run `discover` and `selftest`. They log in to the router, and a
second login clashes with a running service.

```sh
sudo $APP discover
sudo $APP check-config
sudo $APP selftest
```

`discover` lists the device as one root. The device reports no AiMesh list, so the proxy serves it
alone. The service log says `root: no AiMesh list; serving the logged-in device alone`.

```text
role    sys_name     port   model       firmware  ip            mac_tail  online  level  backhaul
router  home-router  16101  RT-EXAMPLE  3.0.0.x   192.168.50.1  00:53:01  yes     0      -
```

`selftest` ends with `OK: all 1 nodes serve`. It exits 0 only then.

## 6. Start the service

```sh
sudo systemctl enable --now aimesh-snmp-proxy
sudo journalctl -u aimesh-snmp-proxy -e
```

The log shows `engine on 127.0.0.1:16101`, then `SERVING`.

## 7. Add the device to LibreNMS

Wait 6 minutes after the start, so the detail is present when LibreNMS first discovers the device.
Then follow [LibreNMS](../librenms.md). In short:

```sh
sudo -u librenms /opt/librenms/lnms config:set icmp_check false
sudo $APP onboard
sudo $APP onboard --apply
sudo -u librenms /opt/librenms/lnms config:set icmp_check true
```

You need an API token and an `[onboard]` table first. Run `init` with `--librenms-url`, or add the
table yourself. `onboard` prints `no ports.json` as a warning. Ignore it: a standalone device has no
node ports to pin.

## What you will see

LibreNMS shows one wireless device with ports for the wired side and every radio, and rows for
the WAN and LAN ports. It shows Wi-Fi clients for each band. See
[Differences by router type](../reference/metrics.md#differences-by-router-type) and
[What LibreNMS shows](../librenms.md#what-librenms-shows). Ports that share a traffic total show
their link state but no traffic. See the
[FAQ](../faq.md#why-do-some-ethernet-ports-show-no-traffic).
