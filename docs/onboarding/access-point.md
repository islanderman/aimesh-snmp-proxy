# Access point

This guide serves a router that runs in access point (AP) mode. It joins your network by cable
and serves Wi-Fi. LibreNMS gets one device. See [Choose your path](index.md) for the overview.

## 1. Prepare the device

1. Find the device in your main router. It has its own LAN address. Reserve that address in the
   DHCP list of the main router, so it does not change.
2. Open the web UI of the access point at its own address. Go to _Administration_, then _System_.
   Set _Authentication Method_ to `HTTPS` or `Both`. Note the HTTPS port. The default is 8443.
3. Note the LAN address of the access point, for example `192.168.50.2`.

## 2. Install the service

Follow [Installation](../installation.md). It leaves the service installed but not started. Stop
every service that polls this device.

## 3. Generate the config

```sh
APP=/opt/aimesh-snmp-proxy/venv/bin/aimesh-snmp-proxy
sudo $APP init --detect --force
```

`init` asks for the address of the device, the HTTPS port, the admin user, the name that LibreNMS
shows, and the admin password. The password prompt does not echo.

Answer the name question with a name of your own, for example `hall-ap`. The default
`aimesh-root` clashes in LibreNMS when you serve a second router.

With `--detect`, `init` then fetches the certificate of the device and prints its SHA-256
fingerprint. Compare it with the one your browser shows for `https://192.168.50.2:8443`. Type `yes` only if
they match. `init` logs in once and finds out that the device has no AiMesh nodes:

```text
detected: a standalone router, AP or media bridge
  root  192.168.50.2  RT-EXAMPLE  online
```

It writes `config.toml`, `asus_password`, a random `snmp_community`, and `asus_router.pem` into
`/etc/aimesh-snmp-proxy`. The installer already made `config.toml` and the empty files, so `--force`
replaces them. Without `--force`, `init` replaces nothing. It prints the next steps.

To answer with flags, see [`init`](../reference/cli.md#init). To write the files yourself, see
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
role    sys_name  port   model       firmware  ip            mac_tail  online  level  backhaul
router  hall-ap   16101  RT-EXAMPLE  3.0.0.x   192.168.50.2  00:53:01  yes     0      -
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
the Ethernet ports. It shows Wi-Fi clients for each band. An access point reports no WAN counter,
so its WAN row has no counters. The wired total goes onto the one port that is up. See
[Differences by router type](../reference/metrics.md#differences-by-router-type),
[What LibreNMS shows](../librenms.md#what-librenms-shows), and the
[FAQ](../faq.md#why-do-some-ethernet-ports-show-no-traffic).
