# netops-field-notes-mcp

The things I check by hand on network gear, as tools your coding agent can call: what changed
between two config snapshots and how much it matters, whether a config passes the CIS/PCI basics,
why a port will not pass 802.1X, which certificates are hiding inside a config and when they expire,
what a device is and what it sits next to, what an OPNsense rule change actually does, and whether a
proposed change is safe to push.

Read-only. Deterministic — no model call, so two engineers get the same answer. No account, no
telemetry, nothing read from your disk: configs and logs go in as text.

## Install

Pin the version.

**Claude Code**

```
claude mcp add netops-field-notes -- uvx --from "git+https://github.com/labaccessnow/netops-field-notes-mcp@v0.1.0" netops-field-notes-mcp
```

**Claude Desktop, Cursor, or any client with a JSON config**

```json
{
  "mcpServers": {
    "netops-field-notes": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/labaccessnow/netops-field-notes-mcp@v0.1.0", "netops-field-notes-mcp"]
    }
  }
}
```

**Docker**

```json
{
  "mcpServers": {
    "netops-field-notes": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "ghcr.io/labaccessnow/netops-field-notes-mcp:0.1.0"]
    }
  }
}
```

Python 3.10 or newer for the uvx route ([uv](https://docs.astral.sh/uv/) installs it). Also in the
official MCP registry as `io.github.labaccessnow/netops-field-notes-mcp`.

## Tools

| Tool | What it answers |
|---|---|
| `explain_config_diff` | What changed between two snapshots, grouped by section, risk-rated, in plain English — EdgeOS, RouterOS, OPNsense, EdgeSwitch, Cisco IOS-style |
| `check_config_compliance` | Does this config pass ten CIS/PCI checks, and what is the one-line fix for each miss |
| `diagnose_dot1x` | Why won't this port authenticate — from the RADIUS log, the switchport config and/or the supplicant log |
| `lookup_ise_failure_code` | What does ISE step code 12514 (or 11036, 22056…) mean and what fixes it |
| `find_certs_in_config` | Which certificates are embedded in this config, and which are expiring, weak or self-signed |
| `check_tls_endpoint` | The same findings on the certificate a public host actually serves |
| `extract_device_facts` | Hostname, role, addresses, subnets, VLANs from a config |
| `infer_topology` | Which of these devices share segments — as a Mermaid diagram |
| `explain_firewall_change` | An OPNsense config.xml change, rule by rule, with risk grounds and shadowing notes |
| `preflight_change` | Is this proposed change safe — risk, compliance regressions, blast radius, a gate verdict |
| `sanitize_config` | Scrub secrets and map addresses consistently before a config goes anywhere |
| `latest_field_note` | What happened in networking this week |

### diagnose_dot1x

The one that saves the most time. Paste what you have — any of the three inputs — and it names the
failure mode rather than restating the log:

```
ROOT CAUSE
Two defects: (1) dot1x failed on an EAP mismatch (EAP-TLS vs EAP-PEAP); (2) MAB then
Accepted with NO dynamic VLAN, so the endpoint landed on VLAN 10 instead of VLAN 30.

RECOMMENDED FIX
1. Align EAP: either enroll a client cert + set the supplicant to EAP-TLS, OR allow EAP-PEAP
   in the ISE auth policy for this port. Make both ends match.
2. Fix the ISE authorization profile "MAB_Guest": add Tunnel-Type=VLAN(13),
   Tunnel-Medium-Type=802(6), Tunnel-Private-Group-ID=30.
3. On the access port add: `authentication event fail action authorize vlan 30` as a local backstop.
```

It knows the difference between a CoA sent to port 1700 and one sent to 3799, an unknown-CA
failure and a missing client certificate, and a `permit any any eq 443` dACL that IOS will reject.

### find_certs_in_config

Web monitors watch ports. Certificates on network gear live in the config — Cisco `crypto pki`
chains, RouterOS exports, OPNsense `<crt>` blobs — and expire without anybody watching. This reads
them out of the text and applies the same rules as the endpoint check: expiry buckets, RSA under
2048, MD5/SHA-1 signatures, self-signed leaves (rated by where they are used), CA certificates
inside 90 days of expiry.

## What it does not do

- No account, no signup, no key. No telemetry.
- Nothing is read from your disk; every input is text you pass in.
- Nothing is written to a device. `preflight_change` tells you what would happen; applying it is
  your job, with the rollback it hands you.
- Two tools open a socket: `check_tls_endpoint` to the host you name (it refuses private and reserved
  addresses, so it cannot be turned on your own network), and `latest_field_note` to a public RSS feed.
- The compliance checks are regex over one config. They catch the obvious; they are not a benchmark run.

## Where this comes from

These are the read-only cores of [DriftWatch](https://driftwatch.labaccessnow.com/) and its siblings,
which run the same rules nightly across a fleet, keep the history, and turn the results into reports.
Here you get the single-shot version on what you paste. That is deliberate — the rules are the useful
part, and they work on their own.

## Licence

MIT. Written by James Son — network, security, and automation engineer — and run against a live
multi-vendor lab before shipping. Corrections welcome, especially to the ISE code table.
