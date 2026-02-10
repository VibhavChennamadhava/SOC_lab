# Consolidated Troubleshooting

This page summarizes recurring issues from the full lab build and PoCs.

---

## 1) Agent active locally but missing in dashboard

### Symptoms

- `systemctl status wazuh-agent` shows `active (running)`
- Agent not visible or disconnected in dashboard

### Root Cause (observed)

- Wrong manager IP used during enrollment (NAT/non-reachable path)

### Fix

```bash
nc -vz <MANAGER_IP> 1514
nc -vz <MANAGER_IP> 1515
sudo systemctl stop wazuh-agent
sudo rm -f /var/ossec/etc/client.keys
sudo /var/ossec/bin/agent-auth -m <MANAGER_IP> -p 1515 -A "ubuntu-agent-01"
sudo systemctl start wazuh-agent
```

### Expected Output

- Port checks succeed
- Agent appears as active in dashboard

---

## 2) Enrollment fails with `invalid agent name`

### Root Cause (observed)

- Stale key/name conflict from previous enrollment

### Fix

- Remove client keys and re-enroll with unique agent name

### Expected Output

- Enrollment succeeds without identity conflict

---

## 3) FIM events missing after config update

### Root Cause (observed)

- Typo in syscheck attribute (`report_changer`)
- Or monitored directory path mismatch

### Fix

```xml
<directories check_all="yes" report_changes="yes" realtime="yes">/home/<USER>/SOC_lab</directories>
```

Then restart agent:

```bash
sudo systemctl restart wazuh-agent
```

### Expected Output

- Rule IDs `554`, `550`, `553` seen for add/modify/delete operations

---

## 4) Rootcheck PoC command breaks after binary swap

### Root Cause (observed)

- Wrapper path typo (`/user/bin/w.copy`)

### Fix

- Use `/usr/bin/w.copy` in wrapper
- Restore original binary after test

### Expected Output

- Wrapper executes and rootcheck alerts are generated

---

## 5) IP reputation alert fires but no firewall-drop action

### Root Cause (observed)

- Rule-to-response mapping mismatch
- Active response block not linked to correct rule ID

### Fix

- Confirm custom rule ID (`100100`) and active response `<rules_id>` match
- Restart manager

```bash
sudo systemctl restart wazuh-manager
```

### Expected Output

- Detection event and block event both visible in dashboard
