# Home-SIEM-Lab
A home lab combining endpoint attack simulation (Atomic Red Team) and network-facing deception (Cowrie honeypot), both monitored through a single Splunk instance.


## Architecture

| Component | Role |
|---|---|
| Windows 10 Home VM | Endpoint: Sysmon + Splunk Universal Forwarder, target of local Atomic Red Team tests |
| Kali Linux VM | Cowrie SSH honeypot, forwards logs to Splunk |
| Splunk Enterprise | SIEM, receiving forwarded events on TCP 9997 |

```text
Windows 10 (Sysmon + Atomic Red Team) ──┐
                                          ├──> Splunk Enterprise
Kali Linux (Cowrie honeypot) ────────────┘
```

## Limitations

- Alerts are not included. Splunk's free/converted license removes alerting, authentication, and distributed search after the 60-day trial ends.
- No Active Directory domain this lab focuses on endpoint telemetry (Sysmon) and network facing deception (honeypot) rather than domain authentication events.

## Repo Structure

```text
README.md
home-lab.md
honeypot.md
Images/
```