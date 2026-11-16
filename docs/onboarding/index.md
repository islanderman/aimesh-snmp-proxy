# Choose your path

Every setup follows the same steps. The guide for your router type lists the exact values and
commands.

| Your device                              | Guide                               |
| ---------------------------------------- | ----------------------------------- |
| An AiMesh root router with AiMesh nodes  | [AiMesh root with nodes](aimesh.md) |
| A router that runs alone, in router mode | [Standalone router](router.md)      |
| A router in access point mode            | [Access point](access-point.md)     |
| A router in media bridge mode            | [Media bridge](media-bridge.md)     |

If you are not sure which mode a device is in, open its web UI and read _Administration_, then
_Operation Mode_. A device with an empty AiMesh list is served as one root device, so the proxy
treats the last three types the same way.

## The seven steps

1. **Prepare the router.** Turn on HTTPS admin login and reserve a fixed address.
2. **Install the service.** See [Installation](../installation.md).
3. **Generate the config.** `init` asks a few questions, pins the router certificate, and writes the
   config and the secrets. You can [write the config by hand](manual.md) instead.
4. **Run the installer again.** The unit reads the router address from the config.
5. **Check.** Run `discover`, `check-config`, and `selftest`.
6. **Start the service.**
7. **Add the devices to LibreNMS.** See [LibreNMS](../librenms.md).

## What you need before you start

| Item                         | Where to find it                                                              |
| ---------------------------- | ----------------------------------------------------------------------------- |
| Router LAN address           | The router web UI, or your DHCP server. The factory default is `192.168.50.1` |
| Admin user name and password | The login of the router web UI                                                |
| HTTPS admin login            | _Administration_, _System_, _Authentication Method_: `HTTPS` or `Both`        |
| HTTPS port                   | The same page. The default is 8443                                            |
| Node addresses               | AiMesh only. `init --detect` finds them for you                               |
| LibreNMS address             | The host that runs LibreNMS                                                   |

The guides use these example values. Replace them with your own.

| Value             | Example                            |
| ----------------- | ---------------------------------- |
| Router            | `192.168.50.1`                     |
| AiMesh nodes      | `192.168.50.11` to `192.168.50.19` |
| The LibreNMS host | `192.168.50.10`                    |

## Tips for every type

- **Use fixed addresses.** Give the router and every node a DHCP reservation. The proxy matches
  nodes by MAC address, but the unit allows traffic only to the addresses you configured.
- **Use the admin account of the router.** The proxy only reads, but its login has full admin
  rights. Protect the password file.
- **Test with the service stopped.** `discover` and `selftest` log in to the router. A second login
  clashes with a running service.
- **Do not paste secrets into a command line.** The commands in these guides read a secret without
  echo and write it to a file with mode 0600.
- **Name each router.** The root device serves the name `aimesh-root`. If you serve more than one
  router, give each one its own name. See [Multiple routers](../instances.md#name-each-router).
