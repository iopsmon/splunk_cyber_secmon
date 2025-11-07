# Hosts Not Reporting Dashboard

## Purpose

The Hosts Not Reporting Dashboard monitors your IT asset inventory and identifies systems that have stopped sending events to Splunk. This is essential for maintaining security visibility, compliance, and operational health.

---

## What It Does

- **Monitors Asset Health**: Tracks which expected systems are actively reporting
- **Identifies Missing Hosts**: Alerts when systems stop sending events
- **Respects Maintenance Windows**: Automatically excludes assets in scheduled downtime
- **Prioritizes Issues**: Highlights critical systems first
- **Provides Visibility**: Shows complete asset status at a glance

---

## Dashboard Overview

### Summary Statistics (Row 1)

**Total Expected Assets**
- Count of all assets that should be reporting
- Based on assets.csv with `is_expected="true"`

**Hosts Not Reporting**
- Assets with no events in the selected time window
- Excludes maintenance windows
- Color-coded: 🟢 Green (<3), 🟡 Yellow (3-5), 🔴 Red (5+)

**Critical Not Reporting**
- Count of critical priority assets offline
- Most urgent - requires immediate attention
- Color-coded: 🟢 Green (0), 🔴 Red (any)

**Reporting Percentage**
- Percentage of expected assets actively sending events
- Target: >95% healthy
- Color-coded: 🔴 Red (<90%), 🟡 Yellow (90-95%), 🟢 Green (>95%)

---

### Detailed Views

**Hosts Not Reporting Table (Row 2)**
- Lists all assets not reporting with full details
- Shows: Asset name, IP, owner, priority, location
- Includes maintenance window and notes
- Sorted by priority (critical first)

**Breakdown Charts (Row 3)**
- By Priority: Which severity levels are affected
- By Category: Servers, workstations, network, laptops
- By Business Unit: Which departments are impacted

**All Assets Status (Row 4)**
- Complete view of every expected asset
- Status: 🟢 Reporting, 🔴 NOT REPORTING, 🟠 In Maintenance
- Shows last seen time and event count
- Hours since last event

**7-Day Trend (Row 5)**
- Reporting health percentage over time
- Identifies patterns and trends
- Shows if situation improving or declining

---

## Filters

### Expected Reporting Window
**Default: Last 24 hours**

How far back to check for events:
- `-24h` - Daily monitoring (recommended)
- `-1h` - Real-time monitoring
- `-7d` - Weekly audit

### Priority Filter
**Options:** All, Critical, High, Medium, Low

Focus on specific asset priorities.

### Category Filter
**Options:** All, Servers, Workstations, Network, Laptops

Filter by asset type.

### Show Assets in Maintenance
**Options:** Exclude (recommended), Include

- **Exclude**: Hides assets in maintenance windows (reduces noise)
- **Include**: Shows all assets regardless of maintenance status

---

## How to Use

### Daily Operations

**Morning Check (30 seconds):**
1. Open dashboard
2. Check "Critical Not Reporting" - should be 🟢 0
3. Review "Hosts Not Reporting" count
4. If red, investigate detail table

**When Issues Found:**
1. Review detail table for missing assets
2. Note owner, location, priority
3. Contact asset owner
4. Check if maintenance is scheduled
5. Investigate cause (network, forwarder, system offline)

---

### Weekly Review (5 minutes)

**Every Monday:**
1. Change time range to `-7d`
2. Review 7-day trend chart
3. Identify persistent missing hosts
4. Update assets.csv (add new, remove decommissioned)
5. Verify maintenance windows are accurate

---

### Monthly Audit (15 minutes)

**First of Month:**
1. Review all assets status table
2. Verify asset inventory is current
3. Check for assets with low event counts
4. Update owner information
5. Generate compliance report

---

## Understanding Results

### Healthy Environment
```
Total Expected: 50
Hosts Not Reporting: 2
Critical Not Reporting: 0
Reporting %: 96% 🟢
```

**Interpretation:** Normal operations. Two missing hosts likely low priority (laptops or dev systems).

**Action:** Review the 2 missing hosts during routine check.

---

### Critical Issue
```
Total Expected: 50
Hosts Not Reporting: 15
Critical Not Reporting: 3
Reporting %: 70% 🔴
```

**Interpretation:** Serious problem affecting 30% of assets including critical systems.

**Actions:**
1. Immediately investigate critical systems
2. Check for network outage
3. Verify Splunk forwarder service status
4. Review recent changes (patching, config changes)
5. Escalate to infrastructure team

---

### Maintenance Window
```
Show Maintenance: Exclude
Hosts Not Reporting: 5

Change to "Include":
Hosts Not Reporting: 10
(5 reporting, 5 in maintenance)
```

**Interpretation:** 5 assets in expected maintenance, 5 unexpected.

**Action:** Investigate the 5 unexpected missing hosts.

---

### Category-Specific Issue
```
Not Reporting by Category:
- Laptops: 12
- Servers: 0
- Workstations: 1
- Network: 0
```

**Interpretation:** Laptop connectivity issue. Infrastructure is healthy.

**Possible Causes:**
- VPN outage
- Wireless network problem
- Forwarder issue on laptop image

---

## Common Scenarios

### Laptop Not Reporting
- **Expected** if user offline/traveling
- **Priority:** Low to Medium
- **Action:** Contact user if >3 days offline

### Server Not Reporting
- **Serious** issue requiring immediate investigation
- **Priority:** High to Critical
- **Action:** Check server status, forwarder service, network connectivity

### Network Device Not Reporting
- **Critical** - may indicate network outage or device failure
- **Priority:** Critical
- **Action:** Check device accessibility, verify syslog configuration

### Workstation Not Reporting
- **Possible** causes: powered off, forwarder stopped
- **Priority:** Medium
- **Action:** Contact user or IT support

---

## Maintenance Windows

### How They Work

Assets with maintenance windows are automatically excluded when "Show Assets in Maintenance" is set to "Exclude" (recommended).

**Maintenance Window Examples:**
- `Sunday 02:00-04:00 UTC` - Scheduled weekly patching
- `Patch Tuesday 2nd Wed of month` - Monthly updates
- `None` - No maintenance, always monitored
- `Anytime` - Flexible maintenance (dev/test systems)
- `Emergency only` - Critical systems (minimal downtime)

**Setting Maintenance Windows:**
Edit `assets.csv` and update the `maintenance_window` field:
```csv
asset,maintenance_window
SERVER-PROD-01,Sunday 02:00-04:00 UTC
WORKSTATION01,Patch Tuesday 2nd Wed of month
FIREWALL-01,Emergency only
```

---

## Troubleshooting

### All Assets Show "NOT REPORTING"

**Possible Causes:**
- No data in Splunk indexes
- Time range too narrow
- Host field name mismatch

**Solutions:**
1. Verify data exists: `index=* earliest=-24h | stats count by host`
2. Increase time range to `-7d`
3. Check host field matches between asset name and Splunk data

---

### Dashboard is Slow

**Cause:** Searching all indexes over long time periods

**Solutions:**
1. Use shorter time range (24h instead of 7d)
2. Specify indexes instead of `index=*`:
   ```
   (index=windows OR index=linux OR index=network)
   ```
3. Schedule dashboard as report instead of real-time

---

### Maintenance Window Not Working

**Cause:** `maintenance_window` field format

**Solution:**
Ensure maintenance_window values are:
- `None` for no maintenance
- Any other text for systems with maintenance

Check with: `| inputlookup assets.csv | stats count by maintenance_window`

---

### Wrong Asset Count

**Cause:** `is_expected` field incorrect

**Solution:**
Verify all active assets have `is_expected="true"`:
```spl
| inputlookup assets.csv
| stats count by is_expected
```

Update assets.csv as needed.

---

## Best Practices

### Set as Homepage
Make this your default dashboard for daily monitoring:
- Settings → User Preferences → Default Dashboard
- Select "Hosts Not Reporting"

### Create Alerts
Set up alerts for critical systems:
- Alert when critical assets not reporting >1 hour
- Send to SOC email/Slack
- Throttle: 1 hour

### Keep Assets.csv Updated
- **Weekly:** Add new assets, remove decommissioned
- **Monthly:** Verify owners and locations
- **Quarterly:** Full audit of all asset data

### Document Patterns
Track recurring issues:
- Which assets frequently offline?
- Common causes of missing data?
- Maintenance window accuracy?

---

## Compliance Use Cases

### GDPR Article 32 - Security of Processing
**Requirement:** Ability to ensure ongoing availability and resilience

**How dashboard helps:**
- Demonstrates continuous monitoring
- Identifies gaps in logging coverage
- Proves availability of audit trails

**Evidence:** Regular dashboard screenshots showing >95% reporting

---

### PCI-DSS Requirement 10.2 - Audit Logs
**Requirement:** All systems in PCI scope must generate logs

**How dashboard helps:**
- Filter to `pci_domain="true"` assets
- Verify 100% PCI systems reporting
- Immediate detection of logging gaps

**Evidence:** Monthly reports showing PCI asset status

---

### SOC 2 - Monitoring Controls
**Requirement:** Continuous monitoring of infrastructure

**How dashboard helps:**
- Daily proof of monitoring activities
- Documentation of issue detection and response
- Audit trail of system availability

**Evidence:** Dashboard access logs, remediation tickets

---

## Key Metrics

### Target: 95% Reporting Rate

**Industry Standards:**
- 🟢 Excellent: >95%
- 🟡 Good: 90-95%
- 🔴 Needs Improvement: <90%

### Critical System SLA

**Target: 0 critical systems not reporting**

Critical systems should never be offline without maintenance notification.

### Mean Time to Detect (MTTD)

**Target: <5 minutes**

Time from system going offline to SOC awareness.

---

## Success Indicators

The dashboard is successful when:
- ✅ Consistently maintaining >95% reporting rate
- ✅ No critical systems missing >1 hour
- ✅ Proactive issue detection (before users report problems)
- ✅ Reduced compliance audit findings
- ✅ Improved mean time to detect infrastructure issues

---

## Related Dashboards

This dashboard is part of the Cyber Security Monitoring App suite:
- **Security Incidents Dashboard**: Manage security alerts and incidents
- **SOC Manager Overview**: Executive KPIs and metrics
- **Hosts Not Reporting**: Asset health monitoring (this dashboard)

---

## Support and Maintenance

### Regular Updates Required

**Asset Inventory:**
- Add new systems as they're deployed
- Mark decommissioned systems as `is_expected="false"`
- Update IP addresses, owners, locations

**Maintenance Windows:**
- Keep maintenance schedules current
- Update after patch schedule changes
- Document emergency maintenance

**Dashboard Tuning:**
- Adjust time ranges based on environment
- Modify color thresholds if needed
- Add custom fields as requirements evolve

---

## Summary

The Hosts Not Reporting Dashboard provides essential visibility into your IT asset health and logging coverage. Use it daily to:

- **Monitor** asset reporting status
- **Detect** offline or misconfigured systems
- **Prioritize** remediation by asset criticality
- **Demonstrate** compliance with logging requirements
- **Maintain** complete security visibility

**Target:** >95% reporting rate with 0 critical systems offline.

---

**Dashboard Version:** 1.0  
**Last Updated:** November 2025  
**Maintained By:** SOC Operations Team
