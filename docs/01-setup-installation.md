# 01 - Setup & Installation (Manager VM + Agent VM)

## Objective

Deploy a working Wazuh lab with:

1. Wazuh stack on Manager VM (Indexer + Manager + Dashboard)
2. Wazuh Agent on Agent VM
3. Agent visibility in Wazuh Dashboard with live event ingestion

---

## Environment / Prerequisites

- Oracle VirtualBox with **two Ubuntu VMs**
- Manager VM reachable from Agent VM over host-only/bridged network
- Required ports open and reachable:
  - `1515/tcp` (enrollment)
  - `1514/tcp` (event forwarding)
  - `443` or `5601` (dashboard)

![Wazuh dashboard reachable](./screenshots/setup/dashboard.png)

---

## Configuration Steps

### 1) Start and verify Wazuh services (Manager VM)

```bash
sudo systemctl start wazuh-indexer wazuh-manager wazuh-dashboard
sudo systemctl enable wazuh-indexer wazuh-manager wazuh-dashboard
sudo systemctl status wazuh-indexer wazuh-manager wazuh-dashboard --no-pager
sudo ss -lntup | egrep '1514|1515|443|5601|9200'
```

**Expected Output**

- All three services show `active (running)`
- Manager listening on `1514` and `1515`
- Dashboard available via `https://<MANAGER_IP>/` or `:5601`

### 2) Validate manager reachability from Agent VM

```bash
nc -vz <MANAGER_IP> 1514
nc -vz <MANAGER_IP> 1515
```

**Expected Output**

- Successful TCP connectivity to both ports

### 3) Enroll and start the Wazuh Agent (Agent VM)

```bash
sudo systemctl stop wazuh-agent
sudo rm -f /var/ossec/etc/client.keys
sudo /var/ossec/bin/agent-auth -m <MANAGER_IP> -p 1515 -A "ubuntu-agent-01"
sudo systemctl start wazuh-agent
sudo systemctl status wazuh-agent --no-pager
sudo tail -n 120 /var/ossec/logs/ossec.log
```

**Expected Output**

- Agent shows `active (running)`
- Log output shows successful registration/connectivity behavior

![Agent deployment and service evidence](./screenshots/setup/agent_deployed.png)

---

## Wazuh Alert Analysis

In Dashboard:

- Go to **Threat Hunting**
- Filter by your agent (example: `agent.name: "ubuntu-agent-01"`)
- Confirm events are arriving after agent start

![Events visible in dashboard](./screenshots/setup/events.png)

---

## Expected Output (End State)

- Agent appears as **Active** in dashboard
- Manager and agent are stable (no repeated reconnect errors)
- Threat Hunting shows events from the enrolled endpoint

---

## Troubleshooting Notes

### Issue 1: Agent running but not visible in dashboard

- **Cause observed:** wrong manager IP (NAT/non-reachable IP used during enrollment)
- **Fix used:** changed manager IP to reachable host-only/bridged IP and re-enrolled

```bash
nc -vz <MANAGER_IP> 1514
nc -vz <MANAGER_IP> 1515
sudo tail -n 200 /var/ossec/logs/ossec.log
```

### Issue 2: `invalid agent name` during enrollment

- **Cause observed:** stale key/duplicate identity conflict
- **Fix used:** cleaned old keys and re-enrolled with unique name

```bash
sudo systemctl stop wazuh-agent
sudo rm -f /var/ossec/etc/client.keys
sudo /var/ossec/bin/agent-auth -m <MANAGER_IP> -p 1515 -A "ubuntu-agent-01"
sudo systemctl start wazuh-agent
```

### Issue 3: Agent config review during debugging

- We reviewed `ossec.conf` on the agent to confirm manager parameters were correct.

![Agent ossec.conf reference](./screenshots/setup/ossec_config_agent.png)

---

## Quick Recruiter Context (SOC relevance)

This setup proves I can:

- Build a working SIEM/XDR lab from scratch
- Troubleshoot real enrollment/networking failures
- Validate log pipeline from endpoint to dashboard with command-level checks
