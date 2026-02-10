# 04 - PoC: IP Reputation Blocking + Active Response (`firewall-drop`)

## Objective

Detect traffic from a reputation-listed IP and trigger Wazuh Active Response (`firewall-drop`) to block it.

---

## Environment / Prerequisites

- Manager VM with Wazuh Manager running
- Agent VM enrolled and sending logs
- Apache or web service running on monitored host during test
- Ability to edit:
  - `/var/ossec/etc/ossec.conf`
  - `/var/ossec/etc/rules/local_rules.xml`

**Assumption:** Based on screenshot evidence, this PoC follows the standard Wazuh AlienVault list ingestion flow and custom rule `100100` tied to active response.

---

## Configuration Steps

### 1) Download and prepare AlienVault reputation list

```bash
sudo wget https://iplists.firehol.org/files/alienvault_reputation.ipset -O /var/ossec/etc/lists/alienvault_reputation.ipset
sudo wget https://wazuh.com/resources/iplist-to-cdblist.py -O /tmp/iplist-to-cdblist.py
sudo /var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py \
  /var/ossec/etc/lists/alienvault_reputation.ipset \
  /var/ossec/etc/lists/blacklist-alienvault
sudo chown wazuh:wazuh /var/ossec/etc/lists/blacklist-alienvault
```

**Expected Output**

- Reputation file downloaded
- CDB list generated at `/var/ossec/etc/lists/blacklist-alienvault`

![Reputation list and conversion commands](./screenshots/poc-ip-reputation/commands.png)

### 2) Register list in ossec.conf

Add list entry under `<ruleset>`:

```xml
<list>etc/lists/blacklist-alienvault</list>
```

**Expected Output**

- Manager config contains custom list registration

![List registration in ossec.conf](./screenshots/poc-ip-reputation/alienvault.png)

### 3) Add custom attack rule (`local_rules.xml`)

```xml
<group name="attack,">
  <rule id="100100" level="10">
    <if_group>web|attack|attacks</if_group>
    <list field="srcip" lookup="address_match_key">etc/lists/blacklist-alienvault</list>
    <description>IP address found in AlienVault reputation database.</description>
  </rule>
</group>
```

**Expected Output**

- Rule `100100` exists and references the CDB list

![Custom local rule for IP reputation](./screenshots/poc-ip-reputation/attack_rule.png)

### 4) Configure Active Response (`firewall-drop`)

In `ossec.conf`:

```xml
<active-response>
  <disabled>no</disabled>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100100</rules_id>
  <timeout>60</timeout>
</active-response>
```

Restart manager:

```bash
sudo systemctl restart wazuh-manager
```

**Expected Output**

- Manager restarts cleanly
- Active response policy tied to rule `100100`

![Active response configuration](./screenshots/poc-ip-reputation/active_response.png)

---

## Attack Simulation / Test Steps

### 1) Ensure target service is running

```bash
sudo systemctl status apache2 --no-pager
```

**Expected Output**

- Apache service is running and reachable

![Apache/web service running](./screenshots/poc-ip-reputation/runningapache.png)

### 2) Generate repeated request traffic (test pattern)

```bash
for i in {1..10}; do
  curl -s -o /dev/null -w "%{http_code}\n" http://<TARGET_IP>/
  sleep 1
done
```

**Expected Output**

- Requests generate HTTP responses initially
- Events are generated for web traffic source IPs

![Attack/test traffic generation](./screenshots/poc-ip-reputation/attacking.png)

---

## Wazuh Alert Analysis

In **Threat Hunting**, filter by custom rule:

```text
rule.id:100100
```

Then confirm active response event appears (e.g., firewall-drop/block event).

**Expected Output**

- Detection event: `IP address found in AlienVault reputation database.` (rule `100100`)
- Follow-up block event indicating `Host Blocked by firewall-drop Active Response`

![Detection and active-response output](./screenshots/poc-ip-reputation/output.png)
![Blocking evidence](./screenshots/poc-ip-reputation/blocking_malactor.png)

---

## Troubleshooting Notes

- **Issue encountered:** command formatting typo during `wget` pipeline caused parse/download errors
- **Fix used:** reran commands carefully, verified final output files under `/var/ossec/etc/lists/`

- **Issue encountered:** no block action observed
- **Fix used:** validated `<active-response>` uses correct `<rules_id>100100</rules_id>`, then restarted `wazuh-manager`

- **Issue encountered:** list updates needed during test
- **Fix used:** appended local entries and reconverted/validated list during debugging

![Local list adjustment note](<./screenshots/poc-ip-reputation/adding localblock.png>)

---

## What this proves for a SOC Analyst role

- I can operationalize threat-intel list matching into actionable detections
- I can create custom Wazuh rules and bind them to automated response
- I can validate both detection and containment behavior with evidence
