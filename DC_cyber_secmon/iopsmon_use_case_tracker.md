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

Verify lookup is accessible:
```spl
| inputlookup iops_security_alerts_summary
```

### Step 3: Detection Development
1. Develop and test the alert SPL
2. Map fields to normalized schema (src_entity, process_info, target_info, additional_context)
3. Validate MITRE ATT&CK mapping
4. Test with sample data and tune thresholds

### Step 4: Alert Deployment
1. Save search as alert in `DC_cyber_secmon` app
2. Configure trigger: `Number of results > 0`
3. Set appropriate throttle/suppression period
4. Schedule using cron (avoid overlapping schedules)
5. Add to `savedsearches.conf` for version control

---

## Active Use Cases

### Summary Table

| Alert ID | Alert Name | Category | Severity | MITRE Technique | Status | Last Updated |
|----------|------------|----------|----------|-----------------|--------|--------------|
| END_ALT-001 | Suspicious Registry Modification via Direct Device Access | Endpoint | Medium | T1112 | Active | Oct 2024 |
| IAM_ALT-001 | Multiple Failed Logons | Identity & Access | Medium | T1110 | Active | Oct 2024 |

---

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
index=attack_data 
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" 
EventCode=13 
Image="\\\\?\\*" 
earliest=0 latest=now
| eval alert_name="Suspicious Registry Modification via Direct Device Access" 
| eval severity="medium" 
| eval mitre_technique_id="T1112" 
| eval mitre_technique_name="Modify Registry" 
| eval mitre_tactic="Defense Evasion"
| eval suspicious_reason="Image path begins with \\\\?\\ (direct device access) - potential evasion technique" 
| eval alert_time=strftime(_time, "%Y-%m-%d %H:%M:%S") 
| stats count BY Image, _time, alert_name, severity, Computer, registry_path, suspicious_reason, mitre_technique_id, mitre_technique_name, mitre_tactic, process_guid, process_id
| where count > 0 
| sort - alert_time
```

#### Alert Configuration (`savedsearches.conf`)
```ini
[END_ALT-001]
action.webhook.enable_allowlist = 0
alert.expires = 15m
alert.suppress = 1
alert.suppress.period = 60m
alert.track = 1
counttype = number of events
cron_schedule = */5 * * * *
description = This monitors for suspicious Registry Modification via Direct Device Access
dispatch.earliest_time = 0
display.events.maxLines = 20
display.general.type = statistics
display.page.search.tab = statistics
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = DC_cyber_secmon
request.ui_dispatch_view = search
search = index=attack_data source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 Image="\\\\?\\C:\\Windows\\system32\\wbem\\WMIADAP.EXE"
disabled = 1
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

---

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

#### Testing Notes
- ✅ Verified detection fires on O365 brute force sample data
- ✅ Alert successfully writes to `notable` index with normalized fields
- ✅ Dashboard displays alerts with proper MITRE mapping
- ✅ Lookup enrichment working correctly
- ⚠️ Schedule set to `*/6 * * * *` (every 6 minutes) - staggered from END_ALT-001 to avoid concurrency
- ⚠️ Suppression period set to `60s` - may need adjustment based on alert volume
- ⚠️ Search period set to `earliest=0` (all time) - change to `-6m` in production

#### Response Guidance
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

#### Lookup Entry
```csv
IAM_ALT-001,Multiple Failed Logons,medium,T1110,Brute Force,Credential Access,Office 365
```

---

## Testing and Production Considerations

### Current Test Configuration Issues

⚠️ **Critical Configuration Notes:**

1. **Search Time Ranges:**
   - Current: `earliest=0 latest=now` (searches all time)
   - Production: Change to `earliest=-5m latest=now` or `earliest=-10m latest=now`
   - Risk: Searching all historical data on every run causes performance issues

2. **Alert Schedules:**
   - END_ALT-001: Every 5 minutes (`*/5 * * * *`)
   - IAM_ALT-001: Every 6 minutes (`*/6 * * * *`)
   - Recommendation: Stagger schedules to avoid concurrent searches
   - Monitor: Check `_internal` logs for search concurrency warnings

3. **Suppression Periods:**
   - END_ALT-001: 60 minutes
   - IAM_ALT-001: 60 seconds
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
| table alert_time, alert_id, alert_name, severity, src_entity, process_info, target_info, additional_context, mitre_technique_id, mitre_tactic, data_source
| collect index=notable sourcetype=notable_events
```

---

## Future Use Cases Pipeline

### Planned Detections

#### Network (NET) Category
- NET_ALT-001: Suspicious Outbound Network Connections
- NET_ALT-002: Large Data Exfiltration
- NET_ALT-003: Beaconing Activity Detection
- NET_ALT-004: Tor/Proxy Network Usage

#### Web (WEB) Category
- WEB_ALT-001: SQL Injection Attempts
- WEB_ALT-002: Command Injection Detection
- WEB_ALT-003: Unusual User-Agent Strings
- WEB_ALT-004: Web Shell Activity

#### Additional Endpoint (END) Category
- END_ALT-002: Suspicious PowerShell Execution
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

## Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | Oct 2025| Initial release with END_ALT-001 | Security Team |
| 1.1 | Oct 2025 | Added IAM_ALT-001 O365 brute force detection | Security Team |

---

## Contact and Support

For questions, issues, or suggestions regarding these use cases:
- Update this documentation with findings
- Share tuning recommendations with the team
- Report false positives for threshold adjustments
- Suggest new detection use cases

---

**Document Status:** Active  
**Last Updated:** October 2024  
**Next Review:** Monthly
