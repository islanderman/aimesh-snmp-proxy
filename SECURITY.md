# Security policy

## Supported versions

Only the latest release gets security fixes. Upgrade first, then report if the problem remains.

## Report a vulnerability

Do not open a public issue. Use
[private vulnerability reporting](https://github.com/islanderman/aimesh-snmp-proxy/security/advisories/new):
open the **Security** tab of this repository and choose **Report a vulnerability**.

Include:

- the version (`aimesh-snmp-proxy --version`) and how you installed it
- the steps to reproduce, and what an attacker gains
- placeholders instead of real passwords, SNMP communities, public IPs and MAC addresses

The maintainer reads every report and aims to reply within 7 days. A fix ships in a new release,
and the advisory credits the reporter unless the reporter asks for no credit.

## What counts

The proxy logs in to a router with a password and answers SNMP on `127.0.0.1` only. These are in
scope:

- a way to make the proxy send a request that changes the router
- a leak of the router password, a session token or an SNMP community into logs, state files or
  SNMP answers
- a way to reach the SNMP ports from another host, or to run code through a crafted router
  response or SNMP request
- a flaw in `deploy/install.sh`, the offline bundle or the systemd units that gives a local user
  more access than intended

Out of scope:

- bugs in router firmware, LibreNMS or other third-party software: report those upstream, and
  tell the maintainer if the proxy makes them worse
- SNMP v2c sending its community in clear text: the proxy listens on loopback for this reason
- a setup that exposes the SNMP ports beyond `127.0.0.1`
