# Wazuh SOC Home Lab Documentation

This repository documents my completed Wazuh SOC home lab with two Ubuntu VMs in VirtualBox:

- **Manager VM**: Wazuh Indexer + Wazuh Manager + Wazuh Dashboard
- **Agent VM**: Wazuh Agent

The goal was to build a practical detection-and-response lab, validate telemetry flow, and document real troubleshooting steps from setup through multiple PoCs.

---

## Lab Overview

### Architecture

- **Platform**: Oracle VirtualBox
- **VM 1 (Manager)**: Hosts Wazuh central stack (Indexer, Manager, Dashboard)
- **VM 2 (Agent)**: Hosts monitored endpoint with Wazuh Agent
- **Core communication**:
  - 1515/TCP for agent enrollment
  - 1514/TCP for event forwarding
  - 443/5601 for dashboard access

![Lab diagram](./docs/screenshots/setup/daigram.png)

---

## Screenshot Setup (Important)

To keep pull requests text-only and avoid binary-file PR errors, screenshots are stored in `screenshots.zip` at the repo root.

Before viewing docs locally, extract the zip into `docs/screenshots/`:

```bash
unzip -o screenshots.zip -d docs/screenshots
```

---

## Documentation Map

- [01 - Setup & Installation](./docs/01-setup-installation.md)
- [02 - PoC: File Integrity Monitoring (FIM)](./docs/02-poc-fim.md)
- [03 - PoC: Rootcheck Trojan Detection](./docs/03-poc-rootcheck-trojan.md)
- [04 - PoC: IP Reputation + Active Response (firewall-drop)](./docs/04-poc-ip-reputation-active-response.md)
- [Troubleshooting (Consolidated)](./docs/troubleshooting.md)

---

## Real Debugging Narrative (What actually happened)

These were the real issues I ran into and fixed during the lab:

- **Agent service was running but not visible in dashboard** because I initially pointed the agent to a non-reachable manager IP (NAT path). I corrected the manager IP to a reachable host-only/bridged interface and reconnected successfully.
- **Enrollment errors (`invalid agent name`)** happened when reusing stale identity/keys. I cleaned existing keys, used a unique agent name, and re-enrolled.
- **Small configuration typo in syscheck** (`report_changer` vs `report_changes`) caused confusion during FIM tuning. I corrected it and documented the exact valid attribute.

---

## Screenshot Index

| Filename | Used In | What It Proves |
|---|---|---|
| `daigram.png` | Setup overview | High-level lab architecture |
| `dashboard.png` | Setup | Wazuh dashboard is reachable |
| `agent_deployed.png` | Setup | Agent enrollment/agent-side activity |
| `events.png` | Setup | Events visible in dashboard |
| `ossec_config_agent.png` | Setup | Agent config file evidence |
| `directories code.png` | FIM | Syscheck `<directories ...>` configuration |
| `filecheck_1.png` | FIM | File create/modify/delete simulation on agent |
| `filecheck_2.png` | FIM | FIM events in dashboard |
| `rootcheck.png` | Rootcheck | Rootcheck-related configuration proof |
| `creating_trojan.png` | Rootcheck | Trojan simulation steps |
| `detected.png` | Rootcheck | Detection shown in dashboard |
| `logs.png` | Rootcheck | Supporting log evidence around detections |
| `commands.png` | IP reputation/AR | Reputation list download + conversion commands |
| `alienvault.png` | IP reputation/AR | `<list>` registration in ruleset |
| `attack_rule.png` | IP reputation/AR | Custom rule `100100` creation |
| `active_response.png` | IP reputation/AR | Active response `firewall-drop` block |
| `attacking.png` | IP reputation/AR | Attack simulation requests |
| `runningapache.png` | IP reputation/AR | Target web service running |
| `blocking_malactor.png` | IP reputation/AR | Evidence of blocked source |
| `output.png` | IP reputation/AR | Detection + active response event output |
| `adding localblock.png` | IP reputation/AR | Local list adjustment/update step |

---

## Notes

- **Assumption:** Based on screenshots, Manager IP appears to be `192.168.56.105` and attacker/agent traffic tests reference `192.168.56.106`.
- This repository keeps the original screenshot filenames to avoid breaking source traceability.
