# LibreNMS

LibreNMS polls each proxy endpoint like an ordinary SNMP device. This page explains what LibreNMS
shows and how to add the devices with `onboard`.

## What LibreNMS shows

Each device the proxy serves appears as one LibreNMS device with the OS `asuswrt-merlin`. The proxy
imitates that OS, so LibreNMS creates its wireless sensors on its own.

[Served metrics](reference/metrics.md) lists every row and where its value comes from. See
[Differences by router type](reference/metrics.md#differences-by-router-type) for what each type
serves. The points below matter most in LibreNMS.

- **Names.** The root serves the sysName `aimesh-root`. A node serves `aimesh-` plus the last six
  hex digits of its MAC address. An `[[override]]` can set another name.
- **Octet counters.** The router reports rates or running totals, not the counters LibreNMS expects.
  The proxy sums them into 64-bit counters and keeps them in `counters.json`, so they never go
  backwards after a restart. A port alias ends in `(derived)` when its counters come from this sum.
- **Ethernet port traffic.** Stock firmware reports no traffic per port. A port gets counters only
  when a total covers that port alone. Ports that share a total show their link state and speed but
  no traffic. See the [FAQ](faq.md#why-do-some-ethernet-ports-show-no-traffic).
- **Uptime.** The root device and a standalone device report their real uptime. A node in
  `root_only` mode reports the time since the proxy began to serve it, so a proxy restart looks like
  a reboot. `per_node` mode reports the real uptime of each node.
- **Wi-Fi clients.** A media bridge serves no Wi-Fi clients, so 0 clients is correct.
- **Links.** Only wireless backhaul links appear under topology. Your switches already report wired
  links over LLDP.
- **Silent devices.** The proxy never serves old data. A node that leaves the AiMesh list, reports
  offline in two polls in a row, or has no data newer than `stale_after_s` does not answer. LibreNMS
  then marks it down.

## Set up LibreNMS before you add devices

### Show the devices as wireless

To list the devices as wireless, set the type of the OS `asuswrt-merlin` once, as the `librenms`
user:

```sh
sudo -u librenms /opt/librenms/lnms config:set os.asuswrt-merlin.type wireless
```

Set it before the first discovery. For devices that already exist, run discovery again.

### Turn ICMP checks off while you add devices

All devices share the address `127.0.0.1`. LibreNMS would file the ping results of every node under
one device. The API cannot turn ICMP off for one device. LibreNMS reads the global `icmp_check`
setting only when it creates a device. So you turn it off before `onboard --apply` and on again
after. Devices created in between keep ICMP off.

## Add the devices with `onboard`

For AiMesh nodes, the service must run first. It pins one SNMP port for each node in `ports.json`,
and `onboard` reads that file. A standalone device has only the root port, `snmp.port_base`, and
never creates `ports.json`. `onboard` then prints a `no ports.json` warning that you can ignore.
`onboard` needs no router login.

The commands below use the folder `/etc/aimesh-snmp-proxy/` of the single service. For an instance,
use its folder, `/etc/aimesh-snmp-proxy/NAME/`, and add `-c /etc/aimesh-snmp-proxy/NAME/config.toml`
after `$APP`. See [Multiple routers](instances.md).

### 1. Make an API token

Create a dedicated LibreNMS user for the token. Grant only what `onboard` needs: list devices, add
devices, and delete devices for `--remove`. Create an API access token for that user in the LibreNMS
web UI.

Store the token in a file. The command asks for it without echo, so it stays out of your history:

```sh
sudo bash -c 'umask 077; read -rsp "API token: " t; echo
  printf %s "$t" >"$0"' /etc/aimesh-snmp-proxy/librenms_token
```

### 2. Pin the LibreNMS certificate

Use an `https://` URL. `onboard` follows a redirect only inside one origin. A redirect from
`http://` to `https://` counts as another origin, and `onboard` refuses it.

If the system trust store does not trust the LibreNMS certificate, pin it. A pinned self-signed
certificate works, even when it names the host only in its common name.

```sh
openssl s_client -connect 192.168.50.10:443 -servername 192.168.50.10 \
  </dev/null 2>/dev/null |
  sudo openssl x509 -out /etc/aimesh-snmp-proxy/librenms.pem
sudo openssl x509 -in /etc/aimesh-snmp-proxy/librenms.pem -noout \
  -fingerprint -sha256
```

Compare the printed fingerprint with the one your browser shows for the LibreNMS site.

### 3. Configure `[onboard]`

Add the table to `config.toml`. See the [configuration keys](reference/configuration.md#onboard).

```toml
[onboard]
url = "https://192.168.50.10"
token_file = "librenms_token"
ca_file = "librenms.pem"
```

Leave out `ca_file` if the system store trusts the certificate. For plain HTTP on the loopback
address, set `url = "http://127.0.0.1"` and add `--allow-http` to each `onboard` command. The token
then travels in cleartext, so use this only on the same host.

By default each LibreNMS device takes the sysName that the node serves. Set `hostname = "ip"` to
name each device by the LAN address of its node instead. The device still serves its sysName.

### 4. Add the devices

Turn ICMP off, run a dry run, apply, and turn ICMP on again:

```sh
APP=/opt/aimesh-snmp-proxy/venv/bin/aimesh-snmp-proxy
sudo -u librenms /opt/librenms/lnms config:set icmp_check false
sudo $APP onboard
sudo $APP onboard --apply
sudo -u librenms /opt/librenms/lnms config:set icmp_check true
```

The dry run prints the planned API calls and sends nothing. Read it before you apply.

`onboard --apply` follows these rules:

- It adds a device only when no device holds its hostname or its SNMP endpoint (`127.0.0.1` and the
  node port). A device you renamed is not added twice. A device that already exists is left
  unchanged. The token's user must be able to see it.
- It adds each device as SNMP v2c with the OS `asuswrt-merlin`, in port order. It writes the SNMP
  community from `community_file` into the request and never prints it.
- It records every device it creates in `onboarded.json` in the state folder.
- It skips a node whose hostname is all digits, because the LibreNMS API reads that as a device ID.
  It skips two nodes that would get the same hostname. Rename one with an `[[override]]`.
- If LibreNMS refuses a checked add, run again with `--force`. LibreNMS may refuse because every
  node shares `127.0.0.1`. `--force` queries each node over SNMP first. It adds the device only if
  the node answers with the expected sysName.

### 5. Clean up

Revoke the API token in LibreNMS. Delete the token and the pin file:

```sh
sudo rm /etc/aimesh-snmp-proxy/librenms_token /etc/aimesh-snmp-proxy/librenms.pem
```

Create a new token and a new pin when you need `onboard` again.

LibreNMS discovers a new device on its next discovery run. To run discovery now, wait until the
service has run for 6 minutes, or 11 in `per_node` mode, then run:

```sh
sudo -u librenms /opt/librenms/lnms device:discover HOSTNAME
```

## Wait before you run discovery

After every start of the service, the detail of each device needs time to return: uptime,
temperatures, RAM, channel frequency, and CPU cores. A detail poll runs every `topology_interval_s`
seconds, 300 by default. CPU cores need two polls, and in `per_node` mode each node polls at its own
offset in the interval. See [CPU and memory](reference/metrics.md#cpu-and-memory) for why.

A discovery in that gap sees no cores and no sensors, so LibreNMS removes them. Wait 6 minutes after
a restart. In `per_node` mode, wait 11 minutes. If you changed `topology_interval_s`, wait that many
seconds plus one minute, or twice that in `per_node` mode. Keep it at 540 or lower. See
[`[collector]`](reference/configuration.md#collector).

If LibreNMS already removed sensors, run discovery again after the detail returns.

Detail also lapses when the polls of one node fail for more than 10 minutes. A discovery then
removes that node's sensors in the same way.

## Change the community of existing devices

LibreNMS 26.x keeps SNMP communities encrypted in its `secrets` table. The device table has no
community column, so you cannot change a community with SQL on it. Change it in the LibreNMS web UI:
open the device, choose _Edit_, then _SNMP_. Do this for every device that the service serves, after
you change `snmp_community` and restart the service.

## Remove the devices

`onboard --remove` deletes only the devices that `onboarded.json` lists. It finds them by device ID,
so devices you renamed are deleted too. It leaves a device alone when it no longer sits at the
endpoint that `onboard` gave it. It needs a valid token and the `[onboard]` table.

```sh
sudo $APP onboard --remove
sudo $APP onboard --remove --apply
```

The first command is a dry run.
