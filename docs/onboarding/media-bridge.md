# Media bridge

This guide serves a router that runs in media bridge mode. It joins your network over Wi-Fi and
gives its LAN ports to wired devices. LibreNMS gets one device. See [Choose your path](index.md) for
the overview.

## 1. Prepare the device

1. Find the bridge in your main router. It has its own LAN address. Reserve that address in the DHCP
   list of the main router, so it does not change.
2. Open the web UI of the bridge at its own address. Go to _Administration_, then _System_. Set
   _Authentication Method_ to `HTTPS` or `Both`. Note the HTTPS port. The default is 8443.
3. Note the LAN address of the bridge, for example `192.168.50.3`.

## 2. Install the service

Follow [Installation](../installation.md). It leaves the service installed but not started. Stop
every service that polls this device.

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

Answer the name question with a name of your own, for example `den-bridge`. The default
`aimesh-root` clashes in LibreNMS when you serve a second router.

With `--detect`, `init` then fetches the certificate of the device and prints its SHA-256
fingerprint. Compare it with the one your browser shows for `https://192.168.50.3:8443`. Type `yes`
only if they match. `init` logs in once and finds out that the device has no AiMesh nodes:

```text
detected: a standalone router, AP or media bridge
  root  192.168.50.3  RT-EXAMPLE  online
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
role    sys_name    port   model       firmware  ip            mac_tail  online  level  backhaul
router  den-bridge  16101  RT-EXAMPLE  3.0.0.x   192.168.50.3  00:53:01  yes     0      -
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

You need an API token and an `[onboard]` table first. You get the table when you give `init` the
LibreNMS address in step 3. Otherwise add it by hand. You create the token file yourself. See
[LibreNMS](../librenms.md). `onboard` prints `no ports.json` as a warning. Ignore it: a standalone
device has no node ports to pin.

## What you will see

LibreNMS shows one device with wireless sensors. It has ports for the wired side and every radio,
and rows for the Ethernet ports. **A media bridge serves no Wi-Fi clients, so LibreNMS shows 0
clients. That is correct.** The radio that links to your main router is the uplink, not an access
point. Wired devices on the bridge ports do not count as Wi-Fi clients. To list the device as
wireless, see [Show the devices as wireless](../librenms.md#show-the-devices-as-wireless).

The Ethernet rows follow what the device reports: link state, speed, and a counter only where a
traffic total covers one port. See
[Differences by router type](../reference/metrics.md#differences-by-router-type),
[What LibreNMS shows](../librenms.md#what-librenms-shows), and the
[FAQ](../faq.md#why-do-some-ethernet-ports-show-no-traffic).
