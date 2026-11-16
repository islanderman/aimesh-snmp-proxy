# Security model

The proxy holds the admin login of your router. This page lists what protects that login, what the
proxy can and cannot do, and where the limits are.

## Summary

| Area           | Control                                                                                  |
| -------------- | ---------------------------------------------------------------------------------------- |
| Process        | Runs as a throwaway `DynamicUser`. Never root, never `librenms`. Sandboxed by systemd    |
| Secrets        | Files in a root-only folder. Reach the service as systemd credentials. Never env or argv |
| Router link    | HTTPS only. Pinned certificates. Read-only request allowlist. Login budget               |
| SNMP           | `127.0.0.1` only. Read-only. A stale node never answers                                  |
| LibreNMS token | Used only by `onboard`. Verified TLS. Revoke after use                                   |
| Install        | Hash-pinned binary wheels. Checksummed bundle                                            |

## Process isolation

The unit runs the service under `DynamicUser=yes`. systemd creates a user for each start and
removes it at stop. The service never runs as root. It refuses to start as root or as `librenms`: a
compromise of those accounts would expose the router login.

The unit applies this sandbox. Run `systemd-analyze security aimesh-snmp-proxy` for the score on your
host.

| Setting                                                                                                                                                 | Effect                                                                                                                                   |
| ------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `IPAddressDeny=any`, `IPAddressAllow=...`                                                                                                               | The service reaches loopback and the router only. The installer sets the list from `asus.host`, plus `nodes.expected` in `per_node` mode |
| `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`                                                                                                      | IP and Unix sockets only                                                                                                                 |
| `NoNewPrivileges=yes`, empty `CapabilityBoundingSet=`                                                                                                   | No privilege gain. No capability. Ports above 1023 need none                                                                             |
| `ProtectSystem=strict`, `ProtectHome=yes`                                                                                                               | The file system is read-only. Only the state folder is writable                                                                          |
| `PrivateTmp=yes`, `PrivateDevices=yes`                                                                                                                  | A private `/tmp`. No device nodes                                                                                                        |
| `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectKernelLogs=yes`, `ProtectControlGroups=yes`, `ProtectClock=yes`, `ProtectHostname=yes` | The kernel and the system are out of reach                                                                                               |
| `ProtectProc=invisible`, `ProcSubset=pid`                                                                                                               | The service sees its own processes only                                                                                                  |
| `RestrictNamespaces=yes`, `RestrictRealtime=yes`, `RestrictSUIDSGID=yes`, `LockPersonality=yes`, `RemoveIPC=yes`                                        | Common escalation paths are closed                                                                                                       |
| `SystemCallFilter=@system-service`, `SystemCallArchitectures=native`                                                                                    | Only ordinary service system calls                                                                                                       |
| `MemoryDenyWriteExecute=yes`                                                                                                                            | No memory is writable and executable at once                                                                                             |
| `MemoryMax=512M`, `TasksMax=128`                                                                                                                        | A runaway process cannot starve the LibreNMS host                                                                                        |
| `UMask=0077`                                                                                                                                            | New files are private                                                                                                                    |

## Secrets

- Secrets live in files in `/etc/aimesh-snmp-proxy`. The folder is mode 0700 and root-owned. Each
  file is mode 0600.
- The unit passes the files to the service with `LoadCredential=`. A secret never travels in an
  environment variable or on a command line. The unit keeps them in a private in-memory folder.
- The loader refuses a secret file that group or others can read, and a file that another user owns.
  It checks POSIX ACLs too.
- From systemd 250, you can encrypt the credentials at rest with `LoadCredentialEncrypted=`. The
  commands you run by hand, such as `selftest`, need plain files.
- The config has no key for a secret value. The loader rejects a key such as `password` and tells
  you to use `password_file`.
- Error messages name a key and a folder, never a value. If you type a secret where a file name
  belongs, the message shows only the folder.
- A log filter masks every registered secret and common secret patterns in every log record. It masks
  the device half of MAC addresses too. Debug output of the SNMP library, which would hexdump
  decrypted packets, stays off at every log level.
- Rotate every secret once a year and after any exposure. See [Operations](operations.md#rotate-secrets).

## Router link

- **HTTPS only.** `asus.use_ssl = false` is an error. The library is set so that it fails a TLS
  problem and never falls back to HTTP.
- **Pinned certificate.** The proxy trusts only the router certificate in `asus.ca_file`. The system
  trust store plays no part. You create the pin with `discover --pin-cert`, which shows the
  fingerprint and writes the file only after you type `yes`. Compare the fingerprint with the one the
  router shows. A mismatch stops the connection before the proxy sends a login.
- **Node certificates.** In `per_node` mode, each node session trusts the CA in `asus.node_ca_file`
  and checks that the node certificate names the node IP. An `[[override]] ca_file` pins one node
  certificate exactly. The proxy accepts only that certificate, even if it is marked as a CA.
- **Read-only.** A request guard checks every request before a connection opens. It allows only
  HTTPS to the configured host and port, and only a fixed list of read pages: login, logout, status
  and diagnostics, traffic, temperature, and port status. It allows `update.cgi` only as a GET for
  `output=netdev`. Every other page, including every page that changes settings, is refused in the
  proxy.
- **Login protection.** Each device the proxy logs in to has a budget of 6 logins per hour. A
  failure backs off with growing delays. A wrong password, a CAPTCHA, or a reset request latches the
  login off until you act, so the proxy never hammers the router. The state is saved before the next
  login, so a restart loop cannot bypass it. The unit stops after 5 failed starts in 15 minutes.
- **Clean sessions.** The proxy logs in once for each device at start, plus one re-login after a
  lost session. It logs out when it stops.

## SNMP side

- The proxy listens on `127.0.0.1` only. The config refuses any other `snmp.bind`, and the unit
  allows only loopback and the router.
- SNMP v2c uses a community that you keep in a root-only file. SNMPv3 offers authPriv with SHA
  authentication (SHA-256 by default) and AES-128 privacy. v2c is clear text, which is acceptable on loopback.
- The engines answer GET, GETNEXT, and GETBULK. They cannot SET. Each engine answers only from the
  table the proxy renders for its device.
- A node that has no fresh data does not answer at all, not even with an SNMPv3 report.
- The proxy serves counts of clients per band and signal statistics. It serves no client name and no
  client MAC address.

## LibreNMS side

`onboard` is the only command that talks to LibreNMS.

- The token travels only in the `X-Auth-Token` header and only to the configured origin.
- TLS is verified against the system store or, with `ca_file`, against the leaf you pinned.
- `http://` needs `--allow-http`. Proxy environment variables are ignored.
- It follows a redirect only for a GET inside the same origin, and it never retries.
- It deletes only the devices it created. It records each in `onboarded.json`.
- Revoke the token after use. A dedicated user with minimal rights limits the damage if it leaks.

## Supply chain

- `uv.lock` pins every dependency by version and hash.
- The release bundle holds the project wheel, the pinned `asusrouter` wheel, and a
  `requirements.txt` that pins every other package by version and hash. The installer downloads
  those packages from PyPI. It runs `pip install --require-hashes --only-binary=:all: --no-deps`
  (or the `uv` equivalent), so it builds nothing, runs no setup script, and rejects a file whose
  hash differs.
- The router library `asusrouter` comes from a pinned git commit. The bundle builder compiles that
  commit into a wheel and records the wheel hash.
- The bundle carries `SHA256SUMS`, and the installer checks it before it changes anything.
- `make audit` checks the locked runtime packages against the PyPI advisory database. It skips
  `asusrouter`, which comes from git and has no PyPI advisories.

## What the proxy does not protect

- A user with root on the host can read every secret and the memory of the service.
- Anyone who knows the router admin password controls the router. The proxy reads only, but its
  password file gives full access. Protect it as you protect the router.
- The proxy cannot tell that a router is compromised. It reports what the router says.
- v2c credentials are not encrypted. Keep `snmp.bind` on loopback.
- LibreNMS stores what the proxy serves: device names, MAC addresses of nodes, and client counts.

## Report a vulnerability

Do not open a public issue for a security problem. Follow the
[security policy](https://github.com/islanderman/aimesh-snmp-proxy/security/policy). It explains how
to send a private report.
