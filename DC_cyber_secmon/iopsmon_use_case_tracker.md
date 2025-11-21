# Cyber Security Use Case Development Tracker

## Overview
This document tracks all active security detection use cases deployed in the Cyber Security Monitoring App. Each use case includes data ingestion details, SPL queries, alert configuration, and testing notes.

---

## Use Case Development Workflow

### Step 1: Data Ingestion
- Ensure attack data sources have been ingested into `attack_data` index
- Identify and verify data source types and field mappings
- Confirm Splunk Technology Add-ons (TAs) are deployed for proper parsing

### Step 2: Alert Metadata Configuration
Add alert metadata to `iops_security_alerts_summary.csv` for dashboard normalization:

```csv
alert_id,alert_name,severity,mitre_technique_id,mitre_technique_name,mitre_tactic,data_source
```

Verify lookups  accessible:
```spl
Contains key security alerts
| inputlookup iops_security_alerts_summary

```

### Step 3: Detection Development
1. Develop and test the alert SPL
2. Map fields to normalized schema (src_entity, process_info, target_info, additional_context)
3. Validate MITRE ATT&CK mapping
4. Test with sample data and tune thresholds
5. Approve Use Case
6. Deploy to Production

### Step 4: Alert Deployment
1. Save search as alert in `DC_cyber_secmon` app
2. Configure trigger: `Number of results > 0`
3. Set appropriate throttle/suppression period
4. Schedule using cron (avoid overlapping schedules)
5. Add to `savedsearches.conf` for version control

---

## Active Use Cases

### Summary Table
- Use this to check which alerts (Use Cases) have been developed 
- These have been deveoped but are examples and develop SPL skills

| Alert ID | Alert Name | Category | Severity | MITRE Technique | Status | Last Updated |
|----------|------------|----------|----------|-----------------|--------|--------------|
| END_ALT-001 | Suspicious Registry Modification via Direct Device Access | Endpoint | Medium | T1112 | Active | Oct 2025 |
| END_ALT-002 | Blocked Process Execution Detected| Endpoint | High| T1059 | Active | Oct 2025 |
| END_ALT-003 | User account has Logged in as root Endpoint | High| T1548.003 | Active | Oct 2025 |
| IAM_ALT-001 | Multiple Failed Logons | Identity & Access | Medium | T1110 | Active | Oct 2025 |
| NET_ALT-001 | Exfiltration Over Web Service | Web Service| High | T1567 | Active | Oct 2025 |
| NET_ALT-002 | AWS Network Port Service Discovery Horizontal | Network | High | T1046 | Active | Nov 2025 |
| WEB_ALT-001 | SQL Injection Attack| Web | High | T1190 | Active | Nov 2025 |
| END_ALT-004 | Suspicious Scheduled Task Creation | Endpoint | High | T1053.005 | Active | Nov 2025 |

---


### DETAILS FOR EACH USE CASES

## ENDPOINT USE CASES

### END_ALT-001: Suspicious Registry Modification via Direct Device Access

#### Overview
**Status:** ✅ Active  
**Category:** Endpoint (END)  
**MITRE ATT&CK:** T1112 - Modify Registry  
**Tactic:** Defense Evasion  
**Severity:** Medium  
**Data Source:** Sysmon EventCode 13  

#### Description
Detects processes using the `\\?\` path prefix to access the Windows registry. This technique is often used by malware to bypass normal path parsing mechanisms and evade detection. The `\\?\` prefix allows direct device access and can be indicative of sophisticated evasion techniques.

#### Attack Data Ingestion
```bash
# Pull the dataset from Splunk Attack Data repository
git lfs pull --include="datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log"

##Push  Data This pushes data as json to HEC 

python3 bin/replay.py datasets/attack_techniques/T1003.001/atomic_red_team/atomic_red_team.yml


# Ingest via manual upload or replay script
# Target index: attack_data
# Sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

#### Detection Logic (SPL)
```spl
index=attack_data  source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 Image="\\\\?\\*" earliest=0 latest=now
| fields _time, source, sourcetype, host, Computer, TargetObject, registry_path,CommandLine EventCode, EventDescription,EventID, EventType, ClientInfo
| eval alert_name="Suspicious Registry Modification via Direct Device Access"
| eval suspicious_reason="Image path begins with \\\\?\\ (direct device access) - potential evasion technique"
| eval event_time = _time 
| eval event_time=strftime(event_time, "%Y-%m-%d %H:%M:%S")
| eval alert_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| lookup iops_security_alerts_summary alert_name OUTPUT alert_id, data_source, mitre_tactic, mitre_technique_id, mitre_technique_name, severity
| eval src_entity=coalesce(Computer, host)
| eval process_info=coalesce(Image, "N/A")
| eval target_info=coalesce(TargetObject, registry_path, "N/A")
| eval additional_context=suspicious_reason
| table _time, alert_id, alert_name, event_time,severity, src_entity, process_info, target_info, additional_context, mitre_technique_id, mitre_tactic, data_source
| collect index=notable
```

#### Alert Configuration (`savedsearches.conf`)
```ini
[END_ALT-001]
action.email.use_ssl = 0
action.webhook.enable_allowlist = 0
alert.expires = 15m
alert.suppress = 1
alert.suppress.period = 60m
alert.track = 1
counttype = number of events
cron_schedule = */5 * * * *
description = This monitors for suspicious Registry Modification via Direct Device Access"
dispatch.earliest_time = 0
display.events.maxLines = 20
display.general.type = statistics
display.page.search.tab = statistics
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = search
request.ui_dispatch_view = search
search = index=attack_data  source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 Image="\\\\?\\*" earliest=0 latest=now\
| fields _time, source, sourcetype, host, Computer, TargetObject, registry_path,CommandLine EventCode, EventDescription,EventID, EventType, ClientInfo\
| eval alert_name="Suspicious Registry Modification via Direct Device Access"\
| eval suspicious_reason="Image path begins with \\\\?\\ (direct device access) - potential evasion technique"\
| eval event_time = _time \
| eval event_time=strftime(event_time, "%Y-%m-%d %H:%M:%S")\
| eval alert_time=strftime(_time, "%Y-%m-%d %H:%M:%S")\
| lookup iops_security_alerts_summary alert_name OUTPUT alert_id, data_source, mitre_tactic, mitre_technique_id, mitre_technique_name, severity\
| eval src_entity=coalesce(Computer, host)\
| eval process_info=coalesce(Image, "N/A")\
| eval target_info=coalesce(TargetObject, registry_path, "N/A")\
| eval additional_context=suspicious_reason\
| table _time, alert_id, alert_name, event_time,severity, src_entity, process_info, target_info, additional_context, mitre_technique_id, mitre_tactic, data_source\
| collect index=notable

```

#### Key Fields
- **EventCode:** 13 (Registry value set)
- **Image:** Process executable path (filter for `\\?\*`)
- **Computer:** Hostname/endpoint name
- **registry_path:** Registry key being modified
- **process_guid:** Unique process identifier
- **process_id:** Process ID

#### Detection Tuning
- **Current Threshold:** Any registry modification using `\\?\` path
- **False Positives:** Legitimate system processes (e.g., WMIADAP.EXE, Windows Update components)
- **Tuning Recommendations:**
  - Whitelist known-good processes: `Image NOT IN ("C:\\Windows\\system32\\wbem\\WMIADAP.EXE")`
  - Focus on high-risk registry paths: `registry_path="*\\CurrentVersion\\Run*" OR registry_path="*\\Services\\*"`
  - Add user context to filter system vs user-initiated changes

#### Testing Notes
- ✅ Verified detection fires on sample attack data
- ✅ Alert successfully writes to `notable` index
- ✅ Dashboard visualization confirmed
- ⚠️ Schedule set to `*/5 * * * *` (every 5 minutes) - monitor for concurrency issues
- ⚠️ Search period set to `earliest=0` (all time) - change to `-5m` or `-10m` in production

#### Response Guidance
1. **Investigate the process:** Check if the Image path is legitimate or suspicious
2. **Review registry modifications:** Determine what was changed and why
3. **Check process parent:** Identify what spawned this process
4. **Examine timeline:** Look for related suspicious activity before/after
5. **Escalate if:** Unknown process, persistence mechanism created, or indicators of malware

### END_ALT-002: Blocked Process Execution Detected

#### Overview
**Status:** ✅ Active  
**Category:** Endpoint (END)  
**MITRE ATT&CK:** T11059 - Execution 
**Tactic:** Command and Scripting Interpreter 
**Severity:** High 
**Data Source:** Sysmon

#### Description
 Sysmon logs detected processes being blocked. This could indicate attempts to execute malicious 
software, unauthorized scripts, or legitimate applications flagged as risky.
The alert classifies the risk level of the blocked processes (e.g., "critical," "high," "medium") 
based on a lookup table that assigns severity scores to known processes and their behaviors.

The alert provides:
    - The name(s) of the blocked process(es).
    - A description from the security database explaining why these processes are considered risky.
    - The number of times each blocked process was executed across different hosts.
    - The unique number of hosts affected by the blocked processes.
MITRE Mapping: The alert links the blocked process activity to specific MITRE ATT&CK tactics and 
techniques, providing a framework for understanding the broader cybersecurity context

#### Attack Data Ingestion
```bash
# Pull the dataset from Splunk Attack Data repository
git lfs pull --include="datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log"

##Push  Data This pushes data as json to HEC 

python3 bin/replay.py datasets/attack_techniques/T1003.001/atomic_red_team/atomic_red_team.yml


# Ingest via manual upload or replay script
# Target index: attack_data
# Sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

#### Detection Logic (SPL)
```spl
index=attack_data sourcetype=XmlWinEventLog source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" process_name=*
earliest=0 
```Pull the fields of interest - imporves searche speed```
| fields _time, source, sourcetype, process_name, Computer, CommandLine, User, Image
```check lookup for blocked exec process - these would be blocked```
| lookup iops_win_exec_process process_name OUTPUT status, category, risk_level, description
| where status="blocked" OR risk_level="critical"
| eval alert_name="Blocked Process Execution Detected"
```Add evals```
| eval suspicious_reason="Execution of blocked process: " . process_name . " - " . description
| eval event_time=strftime(event_time, "%Y-%m-%d %H:%M:%S")
| eval alert_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| eval src_entity=coalesce(Computer, host)
| eval process_info=Image
| eval target_info=coalesce(CommandLine, "N/A")
| eval additional_context=suspicious_reason . " | Risk: " . risk_level . " | Category: " . category . " | User: " . coalesce(User, "Unknown")
| eval event_time = _time
```aggregate using stats```
| stats 
    count as execution_count,
    dc(Computer) as unique_hosts,
    values(Computer) as affected_hosts,
    values(User) as users,
    values(CommandLine) as command_lines,
    min(_time) as first_seen,
    max(_time) as last_seen
    by process_name, event_time, Image, risk_level, category
| where execution_count > 0 
| eval event_time=strftime(event_time, "%Y-%m-%d %H:%M:%S")
| eval alert_time=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| eval alert_name="Blocked Process Execution Detected"
| eval suspicious_reason="Blocked process '" . process_name . "' executed " . execution_count . " times across " . unique_hosts . " host(s)"
| lookup iops_security_alerts_summary alert_name OUTPUT alert_id, data_source, mitre_tactic, mitre_technique_id, mitre_technique_name, severity
| eval src_entity=affected_hosts
| eval process_info=Image
| eval target_info=command_lines
| eval additional_context=suspicious_reason . " | Risk: " . risk_level . " | Users: " . users
| table alert_time, alert_id, alert_name, event_time, severity, src_entity, process_info, target_info, additional_context, mitre_technique_id, mitre_tactic, data_source, execution_count, unique_hosts, risk_level
| sort - execution_count
| collect index=notable

```



#### Alert Configuration (`savedsearches.conf`)
```ini
[END_ALT-002]
action.webhook.enable_allowlist = 0
alert.expires = 30h
alert.suppress = 1
alert.suppress.period = 60s
alert.track = 1
counttype = number of events
cron_schedule = */10 * * * *
description = Blocked Process Execution Detectedl Failed
dispatch.earliest_time = 0
display.events.maxLines = 20
display.general.type = statistics
display.page.search.tab = statistics
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = DC_cyber_secmon
request.ui_dispatch_view = search
search = index=attack_data sourcetype=XmlWinEventLog source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" process_name=*\
earliest=0 \
```check lookup for blocked exec process```\
| lookup iops_win_exec_process process_name OUTPUT status, category, risk_level, description\
| where status="blocked" OR risk_level="critical"\
| eval alert_name="Blocked Process Execution Detected"\
| eval suspicious_reason="Execution of blocked process: " . process_name . " - " . description\
| eval alert_time=strftime(_time, "%Y-%m-%d %H:%M:%S")\
```check for alert id match and normalise the data for dashboards```\
```| lookup iops_security_alerts_summary alert_name OUTPUT alert_id, data_source, mitre_tactic, mitre_technique_id, mitre_technique_name, severity```\
| eval src_entity=coalesce(Computer, host)\
| eval process_info=Image\
| eval target_info=coalesce(CommandLine, "N/A")\
| eval additional_context=suspicious_reason . " | Risk: " . risk_level . " | Category: " . category . " | User: " . coalesce(User, "Unknown")\
```get the stats count ```\
| stats \
    count as execution_count,\
    dc(Computer) as unique_hosts,\
    values(Computer) as affected_hosts,\
    values(User) as users,\
    values(CommandLine) as command_lines,\
    min(_time) as first_seen,\
    max(_time) as last_seen\
    by process_name, Image, risk_level, category\
| where execution_count > 0\
| eval alert_time=strftime(first_seen, "%Y-%m-%d %H:%M:%S")\
| eval alert_name="Blocked Process Execution Detected"\
| eval suspicious_reason="Blocked process '" . process_name . "' executed " . execution_count . " times across " . unique_hosts . " host(s)"\
| lookup iops_security_alerts_summary alert_name OUTPUT alert_id, data_source, mitre_tactic, mitre_technique_id, mitre_technique_name, severity\
| eval src_entity=affected_hosts\
| eval process_info=Image\
| eval target_info=command_lines\
| eval additional_context=suspicious_reason . " | Risk: " . risk_level . " | Users: " . users\
| table alert_time, alert_id, alert_name, severity, src_entity, process_info, target_info, additional_context, mitre_technique_id, mitre_tactic, data_source, execution_count, unique_hosts, risk_level\
| sort - execution_count\
| collect index=notable

```

#### Key Fields
- **process_name:** Unique process name
- **status:** Is the value blocked or allowed 
- **risk_level:** "critical"

#### Detection Tuning
- **False Positives:** Legitimate system processes exec names  (e.g. sysmon64, splunkd.exe, btool.exe)
- **Tuning Recommendations:**
  - Update the lookup file Whitelist: `win_process_exec.csv`
  

#### Testing Notes
- ✅ Verified detection fires on sample attack data
- ✅ Alert successfully writes to `notable` index
- ✅ Dashboard visualization confirmed
- ⚠️ Schedule set to `*/10* * * *` (every 5 minutes) - monitor for concurrency issues
- ⚠️ Search period set to `earliest=0` (all time) - change to `-5m` or `-10m` in production

#### Response Guidance
1. **Investigate the process:** Check if the Image path is legitimate or suspicious
2. **Review allowed processes :** Determine what is allowed and not - check the command CLI
3. **Check process parent:** Identify what spawned this process
4. **Examine timeline:** Look for related suspicious activity before/after
5. **Escalate if:** Unknown process, persistence mechanism created, or indicators of malware



### END_ALT-003: Unauthorised Sudo Privilege Escalation

#### Overview
**Status:** ✅ Active  
**Category:** Endpoint (END)  
**MITRE ATT&CK:** T1548.003  
**Tactic:** Privilege Escalation 
**Severity:** High 
**Data Source:** Linux Secure Logs

#### Description
 Linux Secure logs detected unauthorised users switching to root user processes being blocked. 
 This could indicate attempts to execute malicious commands, exfil run scripts - change config.
software, unauthorized scripts, or legitimate applications flagged as risky.
The alert classifies the risk level of ("critical," "high," "medium") 
based on a lookup table that assigns severity scores to known users their access levels.

The alert provides:
    - The name(s) of the users not authorised to access the server.
    - A description from the security database explaining why these processes are considered risky.
    - The number of times each user swithces to root.
    - The unique number of hosts affected by the users.
MITRE Mapping: The alert links the  activity to specific MITRE ATT&CK tactics and 
techniques, providing a framework for understanding the broader cybersecurity context

#### Attack Data Ingestion
```bash
# The dataset from Splunk Nix TA inputs Attack Data repository
# Ingest via manual upload or replay script
# Target index: index=linux source="/var/log/secure"
# Sourcetype: linux_secure
```

#### Detection Logic (SPL)
```spl
index=linux sourcetype=linux_secure source="/var/log/secure" (process="sudo" OR process="su") earliest=-10m latest=now 
| fields count, _time, _raw, source, sourcetype, action, app, dest, eventtype, host, process, user_name, dvc, priv_username
    ```SUB search ```
| join [search index=linux sourcetype=linux_secure source="/var/log/secure" "session opened for user root" earliest=-10h latest=now 
| rex field=_raw "session opened for user root\(uid=0\) by\s*(?<priv_username>\w+)\("
    ] 
    ```lookup for unauthorised users```
| lookup iops_linux_priv_users priv_username  OUTPUT priv_username, status, description,risk_level,role,team
| where status="unauthorised"
    ```aggreate stats ```
| stats count AS execution_count, values(user_name), values(dest) AS dest, values(host) AS host , values(process) AS process values(priv_username) AS priv_username values(risk_level) as risk_level BY _time, user_name 
| rename values(user_name) AS root_user 
| where (process="su") 
| stats 
    count as execution_count,
    dc(dest) as unique_hosts,
    values(dest) as affected_hosts,
    values(priv_username) as priv_username
    values(risk_level) as risk_level
    values(process) as process_info
    values(dest) as source_ip
    values(_time) as event_time
    min(_time) as first_seen,
    max(_time) as last_seen 
    by user_name, _time 
| where execution_count >= 0 
| eval alert_name="Unauthorised Privilege Escalation" 
| eval suspicious_reason="User account has Logged in as root" 
| lookup iops_security_alerts_summary alert_name OUTPUT alert_id, data_source, mitre_tactic, mitre_technique_id, mitre_technique_name, severity 
| eval event_time=strftime(event_time, "%Y-%m-%d %H:%M:%S") 
| eval alert_time=strftime(first_seen, "%Y-%m-%d %H:%M:%S") 
| eval duration_minutes=round((last_seen - first_seen) / 60, 2) 
| eval target_info=source_ip 
| eval src_entity=priv_username
| eval additional_context=suspicious_reason 
    ```table the results``` 
| table alert_id, alert_name, event_time, severity, src_entity, process_info, target_info, additional_context, mitre_technique_id, mitre_tactic, data_source, execution_count, unique_hosts, risk_level 
| sort - execution_count 
| sort - _time
``` send data to notable```
| collect index=notable
```

#### Alert Configuration (`savedsearches.conf`)
```ini
[END_ALT-003]
action.webhook.enable_allowlist = 0
alert.expires = 60m
alert.suppress = 1
alert.suppress.period = 15m
alert.track = 1
counttype = number of events
cron_schedule = */5 * * * *
description = Unauthorised Privilege Escalation
dispatch.earliest_time = -24h@h
dispatch.latest_time = now
display.events.fields = ["host","source","sourcetype","sudo_user","dvc","COMMAND","USER","process","user_name","original_user"]
display.events.maxLines = 20
display.general.type = statistics
display.page.search.mode = verbose
display.page.search.tab = statistics
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = DC_cyber_secmon
request.ui_dispatch_view = search
search = index=linux sourcetype=linux_secure source="/var/log/secure" (process="sudo" OR process="su") earliest=-10m latest=now \
| fields count, _time, _raw, source, sourcetype, action, app, dest, eventtype, host, process, user_name, dvc, priv_username\
    ```SUB search ```\
| join [search index=linux sourcetype=linux_secure source="/var/log/secure" "session opened for user root" earliest=-10m latest=now \
| rex field=_raw "session opened for user root\(uid=0\) by\s*(?<priv_username>\w+)\("\
    ] \
    ```lookup for unauthorised users```\
| lookup iops_linux_priv_users priv_username  OUTPUT priv_username, status, description,risk_level,role,team\
| where status="unauthorised"\
    ```aggreate stats ```\
| stats count AS execution_count, values(user_name), values(dest) AS dest, values(host) AS host , values(process) AS process values(priv_username) AS priv_username values(risk_level) as risk_level BY _time, user_name \
| rename values(user_name) AS root_user \
| where (process="su") \
| stats \
    count as execution_count,\
    dc(dest) as unique_hosts,\
    values(dest) as affected_hosts,\
    values(priv_username) as priv_username\
    values(risk_level) as risk_level\
    values(process) as process_info\
    values(dest) as source_ip\
    values(_time) as event_time\
    min(_time) as first_seen,\
    max(_time) as last_seen \
    by user_name, _time \
| where execution_count >= 0 \
| eval alert_name="Unauthorised Privilege Escalation" \
| eval suspicious_reason="User account has Logged in as root" \
| lookup iops_security_alerts_summary alert_name OUTPUT alert_id, data_source, mitre_tactic, mitre_technique_id, mitre_technique_name, severity \
| eval event_time=strftime(event_time, "%Y-%m-%d %H:%M:%S") \
| eval alert_time=strftime(first_seen, "%Y-%m-%d %H:%M:%S") \
| eval duration_minutes=round((last_seen - first_seen) / 60, 2) \
| eval target_info=source_ip \
| eval src_entity=priv_username\
| eval additional_context=suspicious_reason \
    ```table the results``` \
| table alert_id, alert_name, event_time, severity, src_entity, process_info, target_info, additional_context, mitre_technique_id, mitre_tactic, data_source, execution_count, unique_hosts, risk_level \
| sort - execution_count \
| sort - _time\
``` send data to notable```
| collect index=notable

```
#### Key Fields
- **sudo_user** Unique user name that run sudo - 
- **username:** Is the value in the lookupfile for privilaged users status = authorised or unauthorised
- **risk_level:** "critical"

#### Detection Tuning
- **False Positives:** Legitimate system processes exec names  (e.g. sysmon64, splunkd.exe, btool.exe)
- **Tuning Recommendations:**
  - Update the lookup file Whitelist: `privileged_users.csv`
  

#### Testing Notes
- ✅ Verified detection fires on sample attack data via nix TA 
- ✅ Alert successfully writes to `notable` index
- ✅ Dashboard visualization confirmed
- ⚠️ Schedule set to `*/5 * * * *` (every 5 minutes) - monitor for concurrency issues
- ⚠️ Search period set to `earliest=0` (all time) - change to `-5m` or `-10m` in production

#### Response Guidance
1. **Investigate the process:** Check if user was allowed the is legitimate or suspicious
2. **Review allowed processes :** Determine what is authorised and not - check policy - RBAC
3. **Examine timeline:** Look for related suspicious activity before/after
5. **Escalate if:** Not authorised




### END_ALT-004: Suspicious Scheduled Task Creation

#### Overview
**Status:** ✅ Active
**Category:** Endpoint (END)
**MITRE ATT&CK:** T1053.005 - Scheduled Task/Job: Scheduled Task
**Tactic:** Persistence, Privilege Escalation, Execution
**Severity:** High
**Data Source:** Sysmon EventCode 1

#### Description
Detects the creation of a scheduled task using `schtasks.exe` with parameters that are commonly associated with malicious activity. This includes tasks that execute `cmd.exe` or `powershell.exe`, tasks configured to run at logon or startup for persistence, or tasks that run with elevated `SYSTEM` privileges. The detection also filters for tasks created by non-privileged accounts, which can be an indicator of unauthorized activity.

#### Attack Data Ingestion
```bash
# Pull the dataset from Splunk Attack Data repository
git lfs pull --include="datasets/attack_techniques/T1053.005/atomic_red_team/windows-sysmon.log"

## Push Data: This pushes data as JSON to HEC
python3 bin/replay.py datasets/attack_techniques/T1053.005/atomic_red_team/atomic_red_team.yml

# Ingest via manual upload or replay script
# Target index: attack_data
# Sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

#### Detection Logic (SPL)
```spl
index=attack_data sourcetype=XmlWinEventLog  source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 Image="*schtasks.exe"CommandLine="*/create*"
earliest=0 latest=now
| where (like(CommandLine, "%cmd.exe%") OR like(CommandLine, "%powershell%") OR like(CommandLine, "%onlogon%") OR like(CommandLine, "%onstart%") OR like(CommandLine, "%/ru system%") OR like(CommandLine, "%/S %"))
| eval task_name=case(
    match(CommandLine, "/tn\s+\"([^\"]+)\""), replace(CommandLine, "(?i).*\/tn\s+\"([^\"]+)\".*", "\1"),
    match(CommandLine, "/tn\s+(\S+)"), replace(CommandLine, "(?i).*\/tn\s+(\S+).*", "\1"),
    1=1, "Unknown"
)
```Lookup for any Windows Priv accounts ```
| lookup iops_win_priv_acccounts account as User OUTPUT account_type
| where isnull(account_type)
| eval alert_name="Suspicious Scheduled Task Creation"
| eval suspicious_reason="Scheduled task created via schtasks.exe with suspicious parameters (cmd/powershell execution, system privileges, or remote execution). Task Name: " + task_name
| eval alert_time=strftime(_time, "%d-%m-%Y %H:%M:%S")
| eval _time=strftime(_time, "%d-%m-%Y %H:%M:%S")
| eval event_time=_time
```Lookup alert details```
| lookup iops_security_alerts_summary alert_name OUTPUT alert_id, data_source, mitre_tactic, mitre_technique_id, mitre_technique_name, severity
| eval src_entity=coalesce(Computer, host)
| eval process_info=coalesce(ParentImage + " -> " + Image + " | " + CommandLine, "N/A")
| eval target_info=coalesce("Task: " + task_name + " | User: " + User, "N/A")
| eval additional_context=suspicious_reason
| table _time, alert_id, alert_name, event_time, severity, src_entity, process_info, target_info, additional_context, mitre_technique_id, mitre_tactic, data_source
| collect index=notable
```

#### Alert Configuration (`savedsearches.conf`)
```ini
[END_ALT-004]
action.webhook.enable_allowlist = 0
alert.expires = 1h
alert.suppress = 0
alert.track = 1
counttype = number of events
cron_schedule = */7 * * * *
description = Windows Suspicious Scheduled Task Creation
disabled = 1
dispatch.earliest_time = -24h@h
dispatch.latest_time = now
display.events.fields = ["host","source","sourcetype","sudo_user","dvc","COMMAND","USER","process","user_name","original_user","uri_path","uri_query","web_method","url","vocab_only","type","msg","general_name","site","password","dest_ip","dest_port","file","page","id","user","username","user_agent","status"]
display.events.maxLines = 20
display.general.type = statistics
display.page.search.tab = statistics
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = DC_cyber_secmon
request.ui_dispatch_view = search
search = index=attack_data sourcetype=XmlWinEventLog  source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 Image="*schtasks.exe"CommandLine="*/create*"\
earliest=0 latest=now\
| where (like(CommandLine, "%cmd.exe%") OR like(CommandLine, "%powershell%") OR like(CommandLine, "%onlogon%") OR like(CommandLine, "%onstart%") OR like(CommandLine, "%/ru system%") OR like(CommandLine, "%/S %"))\
| eval task_name=case(\
    match(CommandLine, "/tn\s+\"([^\"]+)\""), replace(CommandLine, "(?i).*\/tn\s+\"([^\"]+)\".*", "\1"),\
    match(CommandLine, "/tn\s+(\S+)"), replace(CommandLine, "(?i).*\/tn\s+(\S+).*", "\1"),\
    1=1, "Unknown"\
)\
```Lookup for any Windows Priv accounts ```\
| lookup iops_win_priv_acccounts account as User OUTPUT account_type\
| where isnull(account_type)\
| eval alert_name="Suspicious Scheduled Task Creation"\
| eval suspicious_reason="Scheduled task created via schtasks.exe with suspicious parameters (cmd/powershell execution, system privileges, or remote execution). Task Name: " + task_name\
| eval alert_time=strftime(_time, "%d-%m-%Y %H:%M:%S")\
| eval _time=strftime(_time, "%d-%m-%Y %H:%M:%S")\
| eval event_time=_time\
```Lookup alert details```\
| lookup iops_security_alerts_summary alert_name OUTPUT alert_id, data_source, mitre_tactic, mitre_technique_id, mitre_technique_name, severity\
| eval src_entity=coalesce(Computer, host)\
| eval process_info=coalesce(ParentImage + " -> " + Image + " | " + CommandLine, "N/A")\
| eval target_info=coalesce("Task: " + task_name + " | User: " + User, "N/A")\
| eval additional_context=suspicious_reason\
| table _time, alert_id, alert_name, event_time, severity, src_entity, process_info, target_info, additional_context, mitre_technique_id, mitre_tactic, data_source\
| collect index=notable

```

#### Key Fields
- **EventID:** 1 (Process Creation)
- **Image:** `*schtasks.exe`
- **CommandLine:** The full command line used to create the task.
- **ParentImage:** The process that spawned `schtasks.exe`.
- **User:** The user account that created the task.

#### Detection Tuning
- **False Positives:** Legitimate software deployment tools, administrative scripts, or system management solutions might create scheduled tasks that trigger this alert.
- **Tuning Recommendations:**
  - **Whitelist Parent Processes:** Add `ParentImage NOT IN ("C:\\Program Files\\SCCM\\ccmexec.exe", ...)` to exclude tasks created by legitimate management tools.
  - **Whitelist Task Names:** If certain task names are known to be safe, you can add `task_name NOT IN ("Known Good Task")`.
  - **Refine User Lookup:** Ensure the `iops_win_priv_acccounts` lookup is comprehensive to correctly filter out tasks created by authorized administrators.

#### Testing Notes
- ✅ Verified detection fires on sample attack data for T1053.005.
- ✅ Alert successfully writes to the `notable` index with correct normalization.
- ✅ Dashboard visualization confirmed.
- ⚠️ Schedule set to `*/7 * * * *` to avoid concurrency with other alerts.
- ⚠️ Search period should be aligned with the cron schedule (e.g., `-10m`) in production.

#### Response Guidance
1.  **Isolate the host:** Prevent potential lateral movement or further malicious activity.
2.  **Examine the task:** On the affected host, use Task Scheduler or `schtasks /query` to inspect the properties of the created task (`task_name`). Pay close attention to the action (what it runs), the trigger, and the user context.
3.  **Investigate the parent process:** Analyze the `ParentImage`. Was `schtasks.exe` run from an interactive command prompt, a script, or another suspicious process?
4.  **Review associated artifacts:** If the task runs a script or executable, retrieve and analyze that file.
5.  **Remediate:** Delete the malicious scheduled task and any associated files. Review the system for other persistence mechanisms.




## IDENTITY & ACCESS MANAGEMENT (IAM) USE CASES

### IAM_ALT-001: Multiple Failed Logons

#### Overview
**Status:** ✅ Active  
**Category:** Identity & Access Management (IAM)  
**MITRE ATT&CK:** T1110 - Brute Force  
**Tactic:** Credential Access  
**Severity:** Medium  
**Data Source:** Office 365 Management Activity Logs  

#### Description
Detects multiple failed authentication attempts against Office 365 user accounts within a short time window. This pattern is characteristic of brute force attacks where adversaries attempt to guess user credentials through repeated login attempts. The detection tracks failures across multiple source IPs to identify distributed brute force campaigns.

#### Attack Data Ingestion
```bash
# Pull the O365 brute force dataset
git lfs pull --include="datasets/attack_techniques/T1110/"

#Push  Data This pushes data as json to HEC 

python3 bin/replay.py datasets/attack_techniques/T1110/o365_brute_force_login/o365_brute_force_login.yml


# Set environment variables for HEC ingestion
export SPLUNK_HOST="your-splunk-server"
export SPLUNK_HEC_TOKEN="your-hec-token"

# Navigate to attack_data directory and run replay script
cd /Volumes/SANSSD2TB/DEV/CYBER_SEC/SPLUNK_ATTACK_DATA/attack_data
python3 bin/replay.py datasets/attack_techniques/T1110/o365_brute_force_login/o365_brute_force_login.yml

# Target index: attack_data
# Sourcetype: o365:management:activity
# Required TA: Microsoft Office 365 Add-on for Splunk
```

#### Prerequisites
- **Technology Add-on:** Microsoft Office 365 Add-on for Splunk must be installed for proper field extraction
- **Data Collection:** O365 Management Activity API configured and collecting authentication logs
- **Field Mapping:** Verify `src_user`, `src_ip`, `LogonError`, `command` fields are populated

#### Detection Logic (SPL)
```spl
index=attack_data 
sourcetype="o365:management:activity" 
source=o365 
command=UserLoginFailed 
LogonError=InvalidUserNameOrPassword
earliest=0 latest=now
| eval user=coalesce(src_user, user, user_id)
| eval src_ip=coalesce(src_ip, ClientIP, dvc, ActorIpAddress)
| eval logon_type=coalesce(LogonType, logon_type, ApplicationId, event_type, "Unknown")
| eval failure_reason=coalesce(LogonError, ResultDescription, ErrorDescription, "Unknown")
| bucket span=5m _time
| stats 
    count as failed_attempts,
    dc(src_ip) as unique_source_ips,
    values(src_ip) as source_ips,
    values(logon_type) as logon_types,
    values(failure_reason) as failure_reasons,
    min(_time) as first_failure,
    max(_time) as last_failure
    by user
| where failed_attempts >= 3
| eval alert_name="Multiple Failed Logons"
| eval suspicious_reason="User account has " . failed_attempts . " failed login attempts in 5 minute window - potential brute force attack"
| eval alert_time=strftime(first_failure, "%Y-%m-%d %H:%M:%S")
| eval duration_minutes=round((last_failure - first_failure) / 60, 2)
| lookup iops_security_alerts_summary alert_name OUTPUT alert_id, data_source, mitre_tactic, mitre_technique_id, mitre_technique_name, severity
| eval src_entity=user
| eval process_info="N/A"
| eval target_info=source_ips
| eval additional_context=suspicious_reason . " | Unique IPs: " . unique_source_ips . " | Duration: " . duration_minutes . " mins | Reasons: " . failure_reasons
| table alert_time, alert_id, alert_name, severity, src_entity, process_info, target_info, additional_context, mitre_technique_id, mitre_tactic, data_source, failed_attempts, unique_source_ips, logon_types
| sort - failed_attempts
| collect index=notable
```

#### Alert Configuration (`savedsearches.conf`)
```ini
[IAM_ALT-001]
action.webhook.enable_allowlist = 0
alert.expires = 30h
alert.suppress = 1
alert.suppress.period = 60s
alert.track = 1
counttype = number of events
cron_schedule = */6 * * * *
description = Multiple Failed Logons - Detects brute force attempts against O365 accounts
dispatch.earliest_time = 0
display.events.maxLines = 20
display.general.type = statistics
display.page.search.tab = statistics
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = DC_cyber_secmon
request.ui_dispatch_view = search
search = <full SPL from above>
```

#### Key Fields
- **command:** UserLoginFailed (O365 operation type)
- **LogonError:** InvalidUserNameOrPassword (failure reason)
- **src_user:** Username attempting authentication
- **src_ip:** Source IP address of login attempt
- **user_id:** User principal name (email)
- **event_type:** Type of authentication event

#### Detection Tuning
- **Current Threshold:** 3 or more failed attempts in 5-minute window
- **Time Window:** 5 minutes (`bucket span=5m`)
- **False Positives:**
  - Users forgetting passwords (single IP, few attempts)
  - Automated scripts with expired credentials
  - Service accounts with configuration issues
  
- **Tuning Recommendations:**
  - **Increase threshold** to 5+ for noisier environments
  - **Whitelist service accounts:** Add `| search user NOT IN ("serviceaccount@domain.com")`
  - **Geo-location filtering:** Alert only on logins from unexpected countries
  - **Track successful login after failures:** Indicates successful brute force
  - **Multiple source IPs:** Prioritize alerts with `unique_source_ips > 1` (distributed attack)

#### Advanced Detection Variants

##### Variant 1: Successful Login After Multiple Failures
```spl
index=attack_data sourcetype="o365:management:activity" source=o365 
(command=UserLoginFailed OR command=UserLoggedIn)
| eval status=if(command="UserLoggedIn", "success", "failure")
| stats count(eval(status="failure")) as failures, 
        count(eval(status="success")) as successes 
        by user, src_ip
| where failures >= 3 AND successes >= 1
| eval alert_name="Successful Login After Brute Force"
```

##### Variant 2: Distributed Brute Force (Multiple IPs)
```spl
index=attack_data sourcetype="o365:management:activity" 
command=UserLoginFailed
| stats count, dc(src_ip) as unique_ips, values(src_ip) as ips by user
| where count >= 5 AND unique_ips >= 3
| eval alert_name="Distributed Brute Force - Multiple Source IPs"
```



## WEB USE CASES

### WEB_ALT-001: Web Attack Signatures Detected

#### Overview
**Status:** ✅ Active
**Category:** Web (WEB)
**MITRE ATT&CK:** T1190 - Exploit Public-Facing Application
**Tactic:** Initial Access
**Severity:** High
**Data Source:** Nginx Access Logs

#### Description
Detects common web attack patterns in Nginx access logs. This includes signatures for SQL Injection (SQLi), Command Injection, and Path Traversal. The detection identifies suspicious strings in the URI query and alerts when multiple web errors (4xx or 5xx) originate from the same source IP, indicating a potential scanning or exploitation attempt.

#### Attack Data Ingestion
```bash
# Pull the dataset from Splunk Attack Data repository
git lfs pull --include="datasets/attack_techniques/T1190/web_attacks_nginx/web_attacks_nginx.log"

## Push Data This pushes data as json to HEC
python3 bin/replay.py datasets/attack_techniques/T1190/web_attacks_nginx/web_attacks_nginx.yml

# Ingest via manual upload or replay script
# Target index: attack_data
# Sourcetype: nginx:plus:access
```

#### Detection Logic (SPL)
```spl
index=attack_data  sourcetype="nginx:plus:access" earliest=-2h latest=now
| fields host, sourcetype, source, _indextime,_raw,_time,eventtype,file,id,index
```The time is just for testing change to 1 hour for prod```
| rex field=_raw "^(?<src_ip>[^ ]+)\s+\-\s+\-\s+\[(?<timestamp>[^\]]+)\]\s+\"(?<http_method>[^ ]+)\s+(?<uri_path>[^ ]+)\s+(?<http_version>HTTP\/[\d\.]+)\"\s+(?<status>\d{3})\s+(?<bytes_out>[^ ]+)\s+\"(?<referer>[^\"]*)\"\s+\"(?<user_agent>[^\"]+)\""
```search for pattens```
| search (uri_path="*UNION*SELECT*" OR uri_path="*1=1*" OR uri_path="*'  "OR uri_path="*--*" OR uri_path="*;DROP*" OR uri_path="*EXEC*" OR uri_path="UNION*")
```Detect SLQ patterns```
| eval sql_pattern=case(
    match(uri_path, "(?i)UNION.*SELECT"), "UNION SELECT",
    match(uri_path, "(?i)1=1"), "Boolean-based blind",
    match(uri_path, "(?i)' OR"), "OR-based injection",
    match(uri_path, "(?i)--"), "Comment-based injection",
    match(uri_path, "(?i);DROP"), "DROP TABLE attempt",
    match(uri_path, "(?i)EXEC"), "Stored procedure execution",
    1=1, "Unknown SQL pattern"
)
| bucket _time span=5m
```Aggregate the data using stats```
| stats 
    count as request_count,
    dc(uri_path) as unique_paths,
    dc(status) as unique_statuses,
    values(uri_path) as paths,
    values(status) as http_statuses,
    values(http_method) as http_methods,
    values(user_agent) as user_agents,
    values(sql_pattern) as attack_patterns,
    min(_time) as first_seen,
    max(_time) as last_seen   
    by src_ip, host
```Tune here can be over 3 times to reduce noise```    
| where request_count >= 1
```Normalise and lookup for Secuerity App Dashboards Incidents```
| eval alert_name="SQL Injection Attack"
| eval suspicious_reason="SQL injection detected: " . request_count . " attempt(s) using pattern(s): " . attack_patterns
| eval alert_time=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| eval event_time=alert_time
| eval duration_minutes=round((last_seen - first_seen) / 60, 2)
| lookup iops_security_alerts_summary alert_name OUTPUT alert_id, data_source, mitre_tactic, mitre_technique_id, mitre_technique_name, severity
| eval src_entity=src_ip
| eval process_info="HTTP " . http_methods . " request(s)"
| eval target_info=host 
| eval additional_context=suspicious_reason . " | Duration: " . duration_minutes . " mins | HTTP Status: " . http_statuses . " | User-Agent: " . user_agents . " | Paths: " . paths
| table alert_time, alert_id, alert_name, event_time, severity, src_entity, process_info, target_info, additional_context, mitre_technique_id, mitre_tactic, data_source, request_count, unique_paths, attack_patterns, duration_minutes, user_agents
| collect index=notable
```

#### Alert Configuration (`savedsearches.conf`)
```ini
[WEB_ALT-001]
action.webhook.enable_allowlist = 0
alert.expires = 60h
alert.suppress = 1
alert.suppress.period = 60h
alert.track = 1
counttype = number of events
cron_schedule = */15 * * * *
description = SQL Injection Attack
dispatch.earliest_time = 0
display.events.fields = ["host","source","sourcetype","sudo_user","dvc","COMMAND","USER","process","user_name","original_user","uri_path","uri_query","web_method","url","vocab_only","type","msg","general_name","site","password","dest_ip","dest_port","file","page","id","user","username"]
display.events.maxLines = 20
display.general.type = statistics
display.page.search.tab = statistics
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = DC_cyber_secmon
request.ui_dispatch_view = search
search = index=attack_data  sourcetype="nginx:plus:access" earliest=-1h latest=now\
| fields host, sourcetype, source, _indextime,_raw,_time,eventtype,file,id,index\
```The time is just for testing change to 1 hour for prod```\
| rex field=_raw "^(?<src_ip>[^ ]+)\s+\-\s+\-\s+\[(?<timestamp>[^\]]+)\]\s+\"(?<http_method>[^ ]+)\s+(?<uri_path>[^ ]+)\s+(?<http_version>HTTP\/[\d\.]+)\"\s+(?<status>\d{3})\s+(?<bytes_out>[^ ]+)\s+\"(?<referer>[^\"]*)\"\s+\"(?<user_agent>[^\"]+)\""\
```search for pattens```\
| search (uri_path="*UNION*SELECT*" OR uri_path="*1=1*" OR uri_path="*'  "OR uri_path="*--*" OR uri_path="*;DROP*" OR uri_path="*EXEC*" OR uri_path="UNION*")\
```Detect SLQ patterns```\
| eval sql_pattern=case(\
    match(uri_path, "(?i)UNION.*SELECT"), "UNION SELECT",\
    match(uri_path, "(?i)1=1"), "Boolean-based blind",\
    match(uri_path, "(?i)' OR"), "OR-based injection",\
    match(uri_path, "(?i)--"), "Comment-based injection",\
    match(uri_path, "(?i);DROP"), "DROP TABLE attempt",\
    match(uri_path, "(?i)EXEC"), "Stored procedure execution",\
    1=1, "Unknown SQL pattern"\
)\
| bucket _time span=5m\
```Aggregate the data using stats```\
| stats \
    count as request_count,\
    dc(uri_path) as unique_paths,\
    dc(status) as unique_statuses,\
    values(uri_path) as paths,\
    values(status) as http_statuses,\
    values(http_method) as http_methods,\
    values(user_agent) as user_agents,\
    values(sql_pattern) as attack_patterns,\
    min(_time) as first_seen,\
    max(_time) as last_seen   \
    by src_ip, host\
```Tune here can be over 3 times to reduce noise```    \
| where request_count >= 1\
```Normalise and lookup for Secuerity App Dashboards Incidents```\
| eval alert_name="SQL Injection Attack"\
| eval suspicious_reason="SQL injection detected: " . request_count . " attempt(s) using pattern(s): " . attack_patterns\
| eval alert_time=strftime(first_seen, "%Y-%m-%d %H:%M:%S")\
| eval event_time=alert_time\
| eval duration_minutes=round((last_seen - first_seen) / 60, 2)\
| lookup iops_security_alerts_summary alert_name OUTPUT alert_id, data_source, mitre_tactic, mitre_technique_id, mitre_technique_name, severity\
| eval src_entity=src_ip\
| eval process_info="HTTP " . http_methods . " request(s)"\
| eval target_info=host \
| eval additional_context=suspicious_reason . " | Duration: " . duration_minutes . " mins | HTTP Status: " . http_statuses . " | User-Agent: " . user_agents . " | Paths: " . paths\
| table alert_time, alert_id, alert_name, event_time, severity, src_entity, process_info, target_info, additional_context, mitre_technique_id, mitre_tactic, data_source, request_count, unique_paths, attack_patterns, duration_minutes, user_agents\
| collect index=notable

```

#### Key Fields
- **uri_path:** The request URI containing the potential attack payload.
- **src_ip:** The source IP address of the attacker.
- **status:** The HTTP status code (4xx and 5xx errors are of high interest).
- **attack_types:** The classification of the detected attack (SQL Injection, etc.).

#### Detection Tuning
- **False Positives:** Some applications may use URLs that resemble attack patterns. These can be whitelisted. Legitimate vulnerability scanners may also trigger this alert.
- **Tuning Recommendations:**
  - Whitelist trusted IP addresses (e.g., internal vulnerability scanners): `src_ip NOT IN (10.0.0.5, 192.168.1.10)`
  - Adjust the `count` and `error_count` thresholds based on your environment's baseline.
  - Refine the regex patterns for higher fidelity.

#### Testing Notes
- ✅ Verified detection fires on the `web_attacks_nginx.log` sample data.
- ✅ Alert successfully writes to the `notable` index.
- ⚠️ The detection logic uses broad `like` statements. For production, consider using more precise regex (`rex`) for fewer false positives.

#### Response Guidance
1. **Analyze the Source IP:** Check the reputation and geolocation of the `src_ip`. Is it a known bad actor, a Tor exit node, or a cloud provider?
2. **Review the Payloads:** Examine the `suspicious_uris` to understand the attacker's intent. Are they probing for vulnerabilities or actively exploiting a known flaw?
3. **Check Target System Logs:** Correlate the attack with logs on the destination web server. Look for corresponding errors, crashes, or unusual process executions.
4. **Block the IP:** If the activity is confirmed malicious, block the source IP address at the firewall or WAF.
5. **Patch Vulnerabilities:** The attack payloads may indicate the specific vulnerability the attacker is targeting. Ensure your application is patched and up-to-date.

## NETWORK  USE CASES

### NET_ALT-001: Exfiltration Over Web Service

#### Overview
**Status:** ✅ Active  
**Category:** Network  (NET)  
**MITRE ATT&CK:** T1567  Data Exfil   
**Tactic:** Exfiltration Over Web Service
**Severity:** High 
**Data Source:**   Nginx Access Logs

#### Description
This detects data that is being copied to an external web service - the logs are based on the Nginx Access Logs. The rule provides any data going over 100MB threshold will be trigged. 

#### Attack Data Ingestion
```bash
# Pull the dataset from Splunk Attack Data repository
git lfs pull --include="datasets/attack_techniques/T1567/web_upload_nginx/web_upload_nginx.yml"
git lfs pull --include="datasets/attack_techniques/T1567/web_upload_nginx/web_upload_nginx.log"

##Push  Data This pushes data as json to HEC 

python3 bin/replay.py datasets/attack_techniques/T1567/web_upload_nginx/web_upload_nginx.log


# Ingest via manual upload or replay script
# Target index: attack_data
# index=attack_data 
# sourcetype="nginx:plus:access
```

#### Detection Logic (SPL)
```spl
index=attack_data 
sourcetype="nginx:plus:access" 
bytes_out=* 
```the time is so we can get test alerts normally set for 1 hour etc```
earliest=-24h latest=now
| eval GB_bytes_out=round(bytes_out/1024/1024/1024, 2)
```this is to ensure any thing is over 100GB and a POST of data - meaning copied  - you can adjust for testing```
| where (GB_bytes_out >= 0.1 AND http_method="POST")
| bucket _time span=5m
```Main aggregation```
| stats 
    sum(GB_bytes_out) as total_gb_transferred,
    count as request_count,
    dc(uri_path) as unique_paths,
    dc(dest_ip) as unique_destinations,
    values(uri_path) as paths,
    values(http_user_agent) as user_agents,
    values(status) as http_statuses,
    min(_time) as first_seen,
    max(_time) as last_seen
    max(time_local) as raw_local_time
    by src, src_ip, dest_ip, http_method
```If the threshold is over 0.1 100GB ```
| where total_gb_transferred >= 0.1
| eval alert_name="Exfiltration Over Web Service"
| eval suspicious_reason="Large data upload detected: " . round(total_gb_transferred, 2) . " GB transferred via POST in " . request_count . " requests to " . unique_destinations . " destination(s)"
| eval event_time = strftime(strptime(raw_local_time, "%d/%b/%Y:%H:%M:%S %z"), "%Y-%m-%d %H:%M:%S")
| eval alert_time=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| eval duration_minutes=round((last_seen - first_seen) / 60, 2)
```Lookup alert name and get fields  ```
| lookup iops_security_alerts_summary alert_name OUTPUT alert_id, data_source, mitre_tactic, mitre_technique_id, mitre_technique_name, severity
```Normalise fields for incident and reporting dashboards```
| eval src_entity=coalesce(src, src_ip, "Unknown")
| eval process_info="HTTP POST: " . http_method
| eval target_info=dest_ip 
| eval additional_context=suspicious_reason . " | Duration: " . duration_minutes . " mins | Paths: " . paths . " | User-Agents: " . user_agents . " | HTTP Status: " . http_statuses
| table alert_time, event_time, alert_id, alert_name, severity, src_entity, process_info, target_info, additional_context, mitre_technique_id, mitre_tactic, data_source, total_gb_transferred, request_count, unique_destinations, duration_minutes
| sort - total_gb_transferred
| collect index=notable
```

#### Alert Configuration (`savedsearches.conf`)
```ini
[NET_ALT-001]
action.webhook.enable_allowlist = 0
alert.expires = 1h
alert.suppress = 1
alert.suppress.period = 60s
alert.track = 1
counttype = number of events
cron_schedule = */10 * * * *
description = Exfiltration Over Web Service
dispatch.earliest_time = -24h@h
dispatch.latest_time = now
display.events.fields = ["host","source","sourcetype","sudo_user","dvc","COMMAND","USER","process","user_name","original_user","uri_path","uri_query","web_method","url","vocab_only","type","msg","general_name","site"]
display.events.maxLines = 20
display.general.type = statistics
display.page.search.mode = verbose
display.page.search.tab = statistics
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = DC_cyber_secmon
request.ui_dispatch_view = search
search = index=attack_data \
sourcetype="nginx:plus:access" \
bytes_out=* \
```the time is so we can get test alerts normally set for 1 hour etc```\
earliest=-24h latest=now\
| eval GB_bytes_out=round(bytes_out/1024/1024/1024, 2)\
```this is to ensure any thing is over 100GB and a POST of data - meaning copied  - you can adjust for testing```\
| where (GB_bytes_out >= 0.1 AND http_method="POST")\
| bucket _time span=5m\
```Main aggregation```\
| stats \
    sum(GB_bytes_out) as total_gb_transferred,\
    count as request_count,\
    dc(uri_path) as unique_paths,\
    dc(dest_ip) as unique_destinations,\
    values(uri_path) as paths,\
    values(http_user_agent) as user_agents,\
    values(status) as http_statuses,\
    min(_time) as first_seen,\
    max(_time) as last_seen\
    max(time_local) as raw_local_time\
    by src, src_ip, dest_ip, http_method\
```If the threshold is over 0.1 100GB ```\
| where total_gb_transferred >= 0.1\
| eval alert_name="Exfiltration Over Web Service"\
| eval suspicious_reason="Large data upload detected: " . round(total_gb_transferred, 2) . " GB transferred via POST in " . request_count . " requests to " . unique_destinations . " destination(s)"\
| eval event_time = strftime(strptime(raw_local_time, "%d/%b/%Y:%H:%M:%S %z"), "%Y-%m-%d %H:%M:%S")\
| eval alert_time=strftime(first_seen, "%Y-%m-%d %H:%M:%S")\
| eval duration_minutes=round((last_seen - first_seen) / 60, 2)\
```Lookup alert name and get fields  ```\
| lookup iops_security_alerts_summary alert_name OUTPUT alert_id, data_source, mitre_tactic, mitre_technique_id, mitre_technique_name, severity\
```Normalise fields for incident and reporting dashboards```\
| eval src_entity=coalesce(src, src_ip, "Unknown")\
| eval process_info="HTTP POST: " . http_method\
| eval target_info=dest_ip \
| eval additional_context=suspicious_reason . " | Duration: " . duration_minutes . " mins | Paths: " . paths . " | User-Agents: " . user_agents . " | HTTP Status: " . http_statuses\
| table alert_time, event_time, alert_id, alert_name, severity, src_entity, process_info, target_info, additional_context, mitre_technique_id, mitre_tactic, data_source, total_gb_transferred, request_count, unique_destinations, duration_minutes\
| sort - total_gb_transferred\
| collect index=notable


```

#### Key Fields
- **bytes_out:** Size Of Data
- **src_ip:** Source of IP (IP of where the data is being sent to)
- **http_method:** HTTP method showing POST - meaning sending data
- **dest_ip:** This is the IP of the machine where the data is being copied from


#### Detection Tuning
- **Current Threshold:** GB_bytes_out >= 0.1 AND http_method="POST"
- **False Positives:** Check for Legitimate external systems - add lookup if required
- **Tuning Recommendations:**
  - Whitelist known-good IP destinations: `dest_ip NOT IN ("192.168.1.1)`
  - Check size of volume of data  `GB_bytes_out >= 0.1  this is 100GB can go lower if need be`


#### Testing Notes
- ✅ Verified detection fires on sample attack data
- ✅ Alert successfully writes to `notable` index
- ✅ Dashboard visualization confirmed
- ⚠️ Schedule set to `*/5 * * * *` (every 5 minutes) - monitor for concurrency issues
- ⚠️ Search period set to `earliest=0` (all time) - change to `-5m` or `-10m` in production

#### Response Guidance
1. **Investigate the src_ip:** Check if src_ip is legitimate or suspicious
2. **Investiage what user:** Identify what user logged on to the dest_ip target
2. **Investiage what command or script that intitated the copy:** Identify what commands python for example
3. **Examine timeline:** Look for related suspicious activity before/after
4. **Escalate if:** This was not legitimate 


### NET_ALT-002: AWS Network Port Service Discovery Horizontal

#### Overview
**Status:** ✅ Active  
**Category:** Network (NET)  
**MITRE ATT&CK:** T1046 - Network Service Discovery  
**Tactic:** Discovery  
**Severity:** High  
**Data Source:** AWS VPC Flow Logs (`aws:cloudwatchlogs:vpcflow`)

#### Description
Detects a potential network scan where a single source IP attempts to connect to a large number of different ports on a single destination host within your AWS environment. This behavior is indicative of a horizontal port scan, often performed by attackers using tools like Nmap to discover open services for exploitation. This rule aggregates VPC flow logs over a 10-minute window and triggers an alert if more than 20 distinct destination ports are accessed.

#### Attack Data Ingestion
```bash
# Pull the dataset from Splunk Attack Data repository
git lfs pull --include="datasets/attack_techniques/T1046/"

# Push Data: This pushes data as JSON to HEC.
# Note: The specified YAML file was edited to work correctly.
python3 bin/replay.py datasets/attack_techniques/T1046/nmap/nmap_old.yml

# Run the bash script to update the epoch time in the log files
# cd /Volumes/SANSSD2TB/DEV/CYBER_SEC/SPLUNK_ATTACK_DATA/attack_data/datasets/attack_techniques/T1046/nmap 
# ./dc_change_time_horizontal_log.sh
# ./dc_change_time_vertical_log.sh

# Target index: attack_data
# Sourcetype: aws:cloudwatchlogs:vpcflow
```

#### Detection Logic (SPL)
```spl
index=attack_data sourcetype="aws:cloudwatchlogs:vpcflow" source="aws:cloudwatchlogs:vpcflow:vertical.log" earliest=-1h@h latest=now
```The below macro filter is for internal private ranges - commented out for testing```
```| where `filter_private_src_ips```
```scanning vertical logs one host for many ports```
| fields _indextime,_raw,sourcetype,source,_time,account_id,action,vpcflow_action,app,aws_account_id,bytes,dest,dest_ip,dest_port,src_ip, src_port,duration,dvc,end_time,packets, interface_id, protocol vendor_product, transport
```10 minute window```
| bucket _time span=10m
```Aggregate Data```
| stats 
   count as request_count,
    dc(dest_port) as distinct_ports_scanned,
    values(dest_port) as ports_scanned,
    values(action) as actions,
    values(aws_account_id) as aws_account_id,
    min(_time) as first_seen,
    max(_time) as last_seen
    by _time, src_ip, dest_ip
    ```Scanning for more ports than 20 - can be tweaked```
| where distinct_ports_scanned > 20
```Alert Enrichment And Normalization```
| eval alert_name="AWS Network Port Service Discovery Horizontal"
| eval suspicious_reason = src_ip . " performed a network scan " . "Total Ports Scanned " . distinct_ports_scanned . " Account ID " . aws_account_id 
| eval alert_time = strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| eval event_time = strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| lookup iops_security_alerts_summary alert_name OUTPUT alert_id, data_source, mitre_tactic, mitre_technique_id, mitre_technique_name, severity
```Field Normalization for Dashboards```
| eval src_entity = src_ip
| eval process_info = "Nmap Scanning|Script" 
| eval target_info = dest_ip
| eval additional_context = suspicious_reason
| table alert_time, alert_id, alert_name, event_time, severity, src_entity, process_info, target_info, additional_context, mitre_technique_id, mitre_tactic, data_source,request_count
| collect index=notable
```

#### Alert Configuration (`savedsearches.conf`)
```ini
[NET_ALT-002]
action.email.use_ssl = 0
action.webhook.enable_allowlist = 0
alert.expires = 1h
alert.suppress = 1
alert.suppress.period = 60h
alert.track = 1
counttype = number of events
cron_schedule = */7 * * * *
description = AWS Network Port Service Discovery Horiontal
disabled = 1
dispatch.earliest_time = -24h@h
dispatch.latest_time = now
display.events.fields = ["host","source","sourcetype","sudo_user","dvc","COMMAND","USER","process","user_name","original_user","uri_path","uri_query","web_method","url","vocab_only","type","msg","general_name","site","password","dest_ip","dest_port","file","page","id","user","username","user_agent","status"]
display.events.maxLines = 20
display.general.type = statistics
display.page.search.tab = statistics
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = DC_cyber_secmon
request.ui_dispatch_view = search
search = index=attack_data sourcetype="aws:cloudwatchlogs:vpcflow" source="aws:cloudwatchlogs:vpcflow:vertical.log" earliest=-1h@h latest=now\
\
```The below macro filter is for internal private ranges - commented out for testing```\
```| where `filter_private_src_ips```\
```scanning vertical logs one host for many ports```\
| fields _indextime,_raw,sourcetype,source,_time,account_id,action,vpcflow_action,app,aws_account_id,bytes,dest,dest_ip,dest_port,src_ip, src_port,duration,dvc,end_time,packets, interface_id, protocol vendor_product, transport\
``` interesting fields src_ip|action|dest,|dest_ip,|dest_port|aws_account_id```\
```10 minute window```\
| bucket _time span=10m\
```comment  Aggregate Data ```\
| stats \
   count as request_count,\
    dc(dest_port) as distinct_ports_scanned,\
    values(dest_port) as ports_scanned,\
    values(action) as actions,\
    values(aws_account_id) as aws_account_id,\
    min(_time) as first_seen,\
    max(_time) as last_seen\
    by _time, src_ip, dest_ip\
    ```Scanning for more ports than 20 - can be tweaked```\
| where distinct_ports_scanned > 20\
```comment  Alert Enrichment And  Normalization ```\
| eval alert_name="AWS Network Port Service Discovery Horiontal"\
| eval suspicious_reason = src_ip . " performed a network scan " . "Total Ports Scanned " . distinct_ports_scanned . " Account ID " . aws_account_id \
| eval alert_time = strftime(first_seen, "%Y-%m-%d %H:%M:%S")\
| eval event_time = strftime(first_seen, "%Y-%m-%d %H:%M:%S")\
| lookup iops_security_alerts_summary alert_name OUTPUT alert_id, data_source, mitre_tactic, mitre_technique_id, mitre_technique_name, severity\
```comment Field Normalization for Dashboards ```\
| eval src_entity = src_ip\
| eval process_info = "Nmap Scanning|Script" \
| eval target_info = dest_ip\
| eval additional_context = suspicious_reason\
| table alert_time, alert_id, alert_name, event_time, severity, src_entity, process_info, target_info, additional_context, mitre_technique_id, mitre_tactic, data_source,request_count\
| collect index=notable


```

#### Key Fields
- **src_ip:** The source IP address performing the scan.
- **dest_ip:** The target IP address being scanned.
- **distinct_ports_scanned:** The count of unique destination ports contacted.
- **ports_scanned:** The list of destination ports.
- **aws_account_id:** The AWS account where the activity occurred.

#### Detection Tuning
- **Current Threshold:** `distinct_ports_scanned > 20`. This can be raised to reduce noise or lowered to increase sensitivity.
- **False Positives:** Legitimate vulnerability scanners, monitoring tools, or certain applications might trigger this alert.
- **Tuning Recommendations:**
  - Whitelist known good IP addresses of scanners or monitoring tools: `src_ip NOT IN (scanner1_ip, scanner2_ip)`
  - Consider using the `filter_private_src_ips` macro to exclude internal scanning activity if that is expected.

#### Testing Notes
- ✅ Verified detection fires on sample attack data from the `T1046/nmap` dataset.
- ✅ Alert successfully writes to the `notable` index.
- ✅ Dashboard visualization confirmed.
- ⚠️ The `earliest` time should be set to a value appropriate for the cron schedule in production (e.g., `-10m`).

#### Response Guidance
1.  **Immediate Action:** Block the source IP address at the firewall or network ACLs. Alert SOC L2 for further investigation.
2.  **Analysis:** Review firewall/VPC logs to determine the scope of the scan (ports, targets) and check for any successful connections. Correlate the source IP with other log sources to identify further malicious activity.
3.  **Harden:** Review and tighten firewall/security group rules to minimize the external attack surface and restrict access to only necessary ports.





#### IAM_ALT-001 Testing Notes
- ✅ Verified detection fires on O365 brute force sample data
- ✅ Alert successfully writes to `notable` index with normalized fields
- ✅ Dashboard displays alerts with proper MITRE mapping
- ✅ Lookup enrichment working correctly
- ⚠️ Schedule set to `*/6 * * * *` (every 6 minutes) - staggered from END_ALT-001 to avoid concurrency
- ⚠️ Suppression period set to `60s` - may need adjustment based on alert volume
- ⚠️ Search period set to `earliest=0` (all time) - change to `-6m` in production

#### Response Guidance Examples 
1. **Validate the user account:**
   - Is this a real user or service account?
   - Is the account supposed to be active?
   - Check if account is already compromised

2. **Analyze source IPs:**
   - Geo-locate IPs - are they from expected locations?
   - Check IP reputation (VPN, proxy, known malicious)
   - Multiple IPs = distributed attack (more sophisticated)

3. **Check for successful logins:**
   - Did any attempts succeed after failures?
   - If yes, immediately reset password and revoke sessions

4. **Timeline analysis:**
   - Review all O365 activity for this user in the past 24 hours
   - Check for unusual mailbox rules, file downloads, or configuration changes

5. **Escalation criteria:**
   - Successful login after failures = High priority
   - 10+ failed attempts = Investigate immediately
   - Multiple users targeted = Targeted campaign
   - Unusual source countries = Likely malicious

---

## Testing and Production Considerations

### Current Test Configuration Issues

⚠️ **Critical Configuration Notes:**

1. **Search Time Ranges:**
   - Current: `earliest=0 latest=now` (searches all time)
   - Production: Change to `earliest=-5m latest=now` or `earliest=-10m latest=now`
   - Risk: Searching all historical data on every run causes performance issues

2. **Alert Schedules:**
 - These are examples - avoid all at 5 minutes - staggeer them to avoid concurrency issues
   - END_ALT-001: Every 5 minutes (`*/5 * * * *`)
   - END_ALT-002: Every 6 minutes (`*/10 * * * *`)
   - END_ALT-003: Every 5 minutes (`*/5 * * * *`)
   - IAM_ALT-001: Every 6 minutes (`*/6 * * * *`)
   - WEB_ALT-001: Every 10 minutes (`*/15 * * * *`)
   - NET_ALT-001: Every 10 minutes (`*/10 * * * *`)
   - NET_ALT-002: Every 7 minutes (`*/7 * * * *`)

   - Recommendation: Stagger schedules to avoid concurrent searches
   - Monitor: Check `_internal` logs for search concurrency warnings

3. **Suppression Periods:**
   - END_ALT-001: 60 minutes
   - END_ALT-002: 60 minutes
   - END_ALT-003: 60 minutes
   - IAM_ALT-001: 60 seconds
   - WEB_ALT-001: 30 minutes
   - NET_ALT-001: 60 seconds
   - NET_ALT-002: 1 hour

   - Recommendation: Align suppression with schedule frequency to avoid duplicate alerts

### Production Deployment Checklist

Before moving to production:

- [ ] Update `earliest` time in all searches (change from `0` to `-5m` or `-10m`)
- [ ] Verify alert schedules don't overlap
- [ ] Tune thresholds based on baseline testing
- [ ] Add whitelists for known false positives
- [ ] Configure alert actions (email, ticketing)
- [ ] Set appropriate retention for `notable` index
- [ ] Document escalation procedures
- [ ] Train SOC analysts on alert response
- [ ] Test alert suppression/throttling
- [ ] Enable saved search auditing

---

## SPL Best Practices

### Field Normalization Pattern
All alerts should normalize fields to ensure dashboard compatibility:

```spl
| eval src_entity=coalesce(<source_field_options>)
| eval process_info=coalesce(<process_field_options>, "N/A")
| eval target_info=coalesce(<target_field_options>)
| eval additional_context=<context_description>
```

### Lookup Enrichment Pattern
Every alert should enrich with MITRE ATT&CK metadata:

```spl
| lookup iops_security_alerts_summary alert_name OUTPUT alert_id, data_source, mitre_tactic, mitre_technique_id, mitre_technique_name, severity
```

### Notable Index Writing Pattern
Final output should be written to notable index:

```spl
| table alert_time, alert_id, alert_name, event_time, severity, src_entity, process_info, target_info, additional_context, mitre_technique_id, mitre_tactic, data_source
| collect index=notable sourcetype=notable_events
```

---

## Future Use Cases Pipeline

### Planned Detections Examples 

#### Network (NET) Category
- NET_ALT-001: Large Data Exfiltration - DONE
- NET_ALT-002: Suspicious Outbound Network Connections
- NET_ALT-003: Beaconing Activity Detection
- NET_ALT-004: Tor/Proxy Network Usage

#### Web (WEB) Category
- WEB_ALT-001: SQL Injection Attempts
- WEB_ALT-001: Web Attack Signatures Detected - DONE
- WEB_ALT-002: Command Injection Detection
- WEB_ALT-003: Unusual User-Agent Strings
- WEB_ALT-004: Web Shell Activity

#### Additional Endpoint (END) Category
- END_ALT-002: Blocked Process Execution Detected - DONE
- END_ALT-003: Credential Dumping (LSASS Access)
- END_ALT-004: Persistence via Startup Folder
- END_ALT-005: DLL Injection Techniques

#### Additional IAM Category
- IAM_ALT-002: Unusual Login Locations
- IAM_ALT-003: Privilege Escalation Events
- IAM_ALT-004: Suspicious Account Modifications

---

## Troubleshooting Guide

### Alert Not Firing

**Check 1: Verify Data Exists**
```spl
index=attack_data earliest=-24h | stats count by sourcetype, source
```

**Check 2: Test Detection Logic**
```spl
<copy alert SPL without collect command>
```

**Check 3: Check Lookup**
```spl
| inputlookup iops_security_alerts_summary | search alert_id="END_ALT-001"
```

**Check 4: Verify Schedule**
```spl
| rest /servicesNS/-/-/saved/searches splunk_server=local 
| search title="END_ALT-001" 
| table title, disabled, cron_schedule, next_scheduled_time
```

### Alert Not in Notable Index

**Check 1: Verify Notable Index Exists**
```spl
| eventcount summarize=false index=notable
```

**Check 2: Check for Errors**
```spl
index=_internal source=*scheduler.log* "END_ALT-001" ERROR
```

**Check 3: Test Collect Command Manually**
```spl
| makeresults | eval test="value" | collect index=notable
index=notable test=*
```

### Dashboard Not Showing Alerts

**Check 1: Verify Notable Data**
```spl
index=notable earliest=-24h | stats count by source, alert_id
```

**Check 2: Check Time Range**
Ensure dashboard time picker includes alert timestamps

**Check 3: Check Filters**
Verify severity and category filters aren't excluding alerts

---

## Performance Monitoring

### Key Metrics to Track

```spl
# Alert execution time
index=_internal source=*scheduler.log* savedsearch_name="*ALT*"
| stats avg(run_time) as avg_runtime, max(run_time) as max_runtime by savedsearch_name
| eval avg_runtime=round(avg_runtime, 2), max_runtime=round(max_runtime, 2)

# Alert volume
index=notable earliest=-24h 
| timechart span=1h count by alert_id

# Notable index size
| rest /services/data/indexes/notable 
| table title, currentDBSizeMB, totalEventCount

# Search concurrency
index=_internal source=*scheduler.log* status=continued 
| stats count by savedsearch_name
```

---

## Alert Version History

| App Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0.0 | Oct 2025| Initial release with END_ALT-001 | Security Team |
| 1.1.0 | Oct 2025 | Added IAM_ALT-001 O365 brute force detection | Security Team |
| 1.2.0 | Oct 2025 | Added END_ALT-002 sysmon Blocked Process Execution Detected | Security Team |
| 1.2.0 | Oct 2025 | Added END_ALT-003 Unauthorised Sudo Privilege Escalation | Security Team |
| 1.4.0 | Oct 2025 | Added NET_ALT-001 Large Data Exfiltration Security Team |
| 1.5.0 | Oct 2025 | Added WEB_ALT-001 SQL Injection Attack | Security Team |
| 1.6.0 | Nov 2025 | Added NET_ALT-002 AWS Network Port Service Discovery | Security Team |
| 1.7.0 | Nov 2025 | Added END_ALT-004 Suspicious Scheduled Task Creation | Security Team |


---

## Contact and Support

For questions, issues, or suggestions regarding these use cases:
- Update this documentation with findings
- Share tuning recommendations with the team
- Report false positives for threshold adjustments
- Suggest new detection use cases

---

**Document Status:** Active  
**Last Updated:** November 2025  
**Next Review:** Monthly

