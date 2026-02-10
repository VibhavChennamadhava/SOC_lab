# 03 - PoC: Rootcheck Trojan Detection

## Objective

Demonstrate Wazuh Rootcheck detection by simulating a trojanized system utility in a reversible lab-safe workflow.

---

## Environment / Prerequisites

- Wazuh Agent installed and connected
- Root privileges on agent VM
- Rootcheck enabled in `/var/ossec/etc/ossec.conf`

---

## Configuration Steps

### 1) Verify Rootcheck configuration

```bash
sudo grep -A 6 "<rootcheck>" /var/ossec/etc/ossec.conf
```

Expected block:

```xml
<rootcheck>
  <disabled>no</disabled>
  <check_files>yes</check_files>
  <check_trojans>yes</check_trojans>
  <frequency>43200</frequency>
</rootcheck>
```

**Expected Output**

- Rootcheck is enabled (`<disabled>no</disabled>`)

![Rootcheck configuration reference](./screenshots/poc-rootcheck/rootcheck.png)

---

## Attack Simulation / Test Steps

### 1) Backup binary

```bash
sudo cp -a /usr/bin/w /usr/bin/w.copy
ls -l /usr/bin/w /usr/bin/w.copy
```

**Expected Output**

- Both files exist with executable permissions

### 2) Replace `/usr/bin/w` with wrapper script

```bash
sudo tee /usr/bin/w > /dev/null <<'EOF2'
#!/bin/bash
echo "$(date) this is evil" > /tmp/trojan_created_file
echo "test for /usr/bin/w trojaned file" >> /tmp/trojan_created_file
/usr/bin/w.copy "$@"
EOF2

sudo chmod +x /usr/bin/w
```

**Expected Output**

- Wrapper file created and executable

### 3) Execute and verify artifact

```bash
/usr/bin/w | head
cat /tmp/trojan_created_file
```

**Expected Output**

- Command runs and writes `/tmp/trojan_created_file`

![Trojan creation step](./screenshots/poc-rootcheck/creating_trojan.png)

---

## Trigger Detection

```bash
sudo systemctl restart wazuh-agent
sudo tail -n 200 /var/ossec/logs/ossec.log | grep -i rootcheck
```

**Expected Output**

- Log lines indicate rootcheck activity

---

## Wazuh Alert Analysis

In Dashboard (**Threat Hunting**), test queries:

```text
location:rootcheck
```

```text
location:rootcheck AND rule.id:510
```

**Expected Output**

- Alert(s) showing suspicious binary tampering/trojan indicator tied to `/usr/bin/w`

![Rootcheck detection in dashboard](./screenshots/poc-rootcheck/detected.png)
![Supporting log view](./screenshots/poc-rootcheck/logs.png)

---

## Cleanup / Restore

```bash
sudo mv -f /usr/bin/w.copy /usr/bin/w
sudo rm -f /tmp/trojan_created_file
sudo systemctl restart wazuh-agent
ls -l /usr/bin/w
test -f /tmp/trojan_created_file && echo "Cleanup failed" || echo "Cleanup successful"
```

**Expected Output**

- Original binary restored
- Temporary trojan artifact removed

---

## Troubleshooting Notes

- **Issue encountered:** Wrapper typo (`/user/bin/w.copy`) can break command execution
- **Fix used:** corrected to `/usr/bin/w.copy`

- **Issue encountered:** No immediate alert after trojan creation
- **Fix used:** restarted agent and checked `ossec.log` for rootcheck scan execution

---

## What this proves for a SOC Analyst role

- I can safely simulate host tampering indicators in a controlled environment
- I can correlate endpoint behavior and SIEM detections
- I can execute a complete test cycle, including post-test cleanup
