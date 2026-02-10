# 02 - PoC: File Integrity Monitoring (FIM)

## Objective

Validate Wazuh FIM by detecting file **creation, modification, and deletion** in a monitored directory on the Agent VM.

---

## Environment / Prerequisites

- Manager VM and Agent VM already connected
- Agent appears active in dashboard
- Access to edit `/var/ossec/etc/ossec.conf` on agent

---

## Configuration Steps

### 1) Create a dedicated test directory (Agent VM)

```bash
sudo mkdir -p /home/<USER>/SOC_lab
sudo chown -R <USER>:<USER> /home/<USER>/SOC_lab
```

**Expected Output**

- Directory exists and is writable by `<USER>`

### 2) Configure syscheck for realtime FIM

Edit:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Inside `<syscheck>`, add:

```xml
<directories check_all="yes" report_changes="yes" realtime="yes">/home/<USER>/SOC_lab</directories>
```

**Expected Output**

- Valid syscheck directory rule present
- Attribute is exactly `report_changes` (not `report_changer`)

![FIM directories config](<./screenshots/poc-fim/directories code.png>)

### 3) Restart agent

```bash
sudo systemctl restart wazuh-agent
sudo tail -n 200 /var/ossec/logs/ossec.log | grep -i syscheck
```

**Expected Output**

- Agent restarts successfully
- Log output references syscheck/FIM activity

---

## Attack Simulation / Test Steps

Run from Agent VM:

```bash
# Create
echo "v1" > /home/<USER>/SOC_lab/test.txt
sleep 5

# Modify
echo "v2" >> /home/<USER>/SOC_lab/test.txt
sleep 5

# Delete
rm -f /home/<USER>/SOC_lab/test.txt
```

**Expected Output**

- Commands execute without permission/path errors
- Three state changes are generated for the same file

![FIM test commands on agent](./screenshots/poc-fim/filecheck_1.png)

---

## Wazuh Alert Analysis

In dashboard:

- Go to **File Integrity Monitoring → Events**
- Use filter:

```text
rule.id: is one of 550,553,554
```

Optional narrowing:

```text
agent.name: "<YOUR_AGENT_NAME>"
syscheck.path: "/home/<USER>/SOC_lab/test.txt"
```

**Expected Output**

- Rule `554` for file add
- Rule `550` for file modify
- Rule `553` for file delete

![FIM events in dashboard](./screenshots/poc-fim/filecheck_2.png)

---

## Troubleshooting Notes

- **Issue encountered:** Path confusion while testing (`/vibe/SOC_lab/test.txt` vs actual home path)
- **Fix used:** Confirmed current directory/user and used full absolute path under `/home/<USER>/...`

- **Issue encountered:** No events after config edit
- **Fix used:** Verified typo correction from `report_changer` to `report_changes`, then restarted agent

---

## What this proves for a SOC Analyst role

- I can implement and tune endpoint integrity monitoring
- I can map low-level events to specific Wazuh rule IDs for triage
- I can debug noisy/misconfigured FIM quickly and validate with evidence
