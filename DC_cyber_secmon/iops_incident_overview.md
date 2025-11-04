# Incident Management System - Complete Guide

## Overview

The Incident Management System is a complete incident tracking and workflow solution built within Splunk for the Cyber Security Monitoring App. It provides SOC analysts with the ability to create, update, and manage security incidents directly from notable alerts.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Components](#components)
3. [Installation Guide](#installation-guide)
4. [User Guide](#user-guide)
5. [Technical Details](#technical-details)
6. [Troubleshooting](#troubleshooting)
7. [Best Practices](#best-practices)

---

## Architecture Overview

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Notable Alerts                           │
│              (notable index)                                │
│  - Alert ID, Name, Severity                                 │
│  - MITRE ATT&CK Mapping                                     │
│  - Source Entity, Context                                   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│           Incident Management Dashboard                     │
│  - View Incidents                                           │
│  - Create from Alerts                                       │
│  - Update Status/Assignment                                 │
│  - Delete Incidents                                         │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│               KVStore Collection                            │
│           (security_incidents)                              │
│  - Persistent incident storage                              │
│  - Indexed for fast queries                                 │
│  - Tracks incident lifecycle                                │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Alert Generation**: Security detections write to `notable` index
2. **Incident Creation**: SOC analyst creates incident from notable alert
3. **Incident Storage**: Incident written to KVStore (`security_incidents` collection)
4. **Incident Management**: Analysts update status, reassign, or close incidents
5. **Reporting**: Dashboard provides real-time visibility into incident pipeline

---

## Components

### 1. KVStore Collection (`security_incidents`)

**Location:** `collections.conf`

**Purpose:** Persistent storage for all incident data

**Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `incident_id` | string | Unique identifier (INC-timestamp) |
| `alert_id` | string | Source alert ID (e.g., END_ALT-001) |
| `alert_name` | string | Name of triggering alert |
| `severity` | string | Incident severity (critical, high, medium, low) |
| `status` | string | Current status (open, investigating, closed) |
| `assigned_to` | string | SOC analyst assigned to incident |
| `created_time` | time | When incident was created (epoch) |
| `updated_time` | time | Last modification time (epoch) |
| `src_entity` | string | Affected host/user/IP |
| `mitre_technique_id` | string | MITRE ATT&CK technique |
| `mitre_tactic` | string | MITRE ATT&CK tactic |
| `description` | string | Incident description |
| `notes` | string | Investigation notes |

### 2. SOC Users Lookup (`soc_users.csv`)

**Location:** `lookups/soc_users.csv`

**Purpose:** List of SOC team members for incident assignment

**Fields:**
| Field | Description | Example |
|-------|-------------|---------|
| `username` | Splunk username | john.smith |
| `full_name` | Display name | John Smith |
| `email` | Contact email | john.smith@company.com |
| `role` | Job title | SOC Analyst L1 |
| `team` | Department | Security Operations |
| `status` | Active or inactive | active |

### 3. Incidents Dashboard (`incidents_dashboard.xml`)

**Location:** `default/data/ui/views/incidents_dashboard.xml`

**Purpose:** Main UI for incident management

**Sections:**
- **Filters**: Status, Severity, Assigned User
- **Summary Statistics**: Total, Open, Investigating, Unassigned counts
- **Visualizations**: Charts by status, severity, MITRE tactic
- **Incident Details Table**: Full incident listing
- **Assignment Summary**: Workload by analyst
- **Create Incident**: Form to create from notable alerts
- **Update Incident**: Form to modify status/assignment
- **Delete Incident**: Form to remove closed incidents

### 4. JavaScript Handler (`create_incident.js`)

**Location:** `appserver/static/create_incident.js`

**Purpose:** Client-side logic for incident operations

**Functions:**
- `Create Incident Handler`: Fetches alert data, generates incident ID, writes to KVStore
- `Update Incident Handler`: Modifies existing incident status and assignment
- `Delete Incident Handler`: Removes incident from KVStore

---

## Installation Guide

### Prerequisites

- Splunk Enterprise or Cloud
- DC_cyber_secmon app installed
- Notable alerts generating (END_ALT-001, IAM_ALT-001, etc.)
- Admin or power user permissions

---

### Stage 1: KVStore Setup

#### Step 1: Create collections.conf

**File:** `$SPLUNK_HOME/etc/apps/DC_cyber_secmon/local/collections.conf`

```ini
[security_incidents]
enforceTypes = true
field.incident_id = string
field.alert_id = string
field.alert_name = string
field.severity = string
field.status = string
field.assigned_to = string
field.created_time = time
field.updated_time = time
field.src_entity = string
field.mitre_technique_id = string
field.mitre_tactic = string
field.description = string
field.notes = string

accelerated_fields.incident_lookup = {"incident_id": 1, "status": 1, "severity": 1, "assigned_to": 1}
```

#### Step 2: Create transforms.conf

**File:** `$SPLUNK_HOME/etc/apps/DC_cyber_secmon/local/transforms.conf`

```ini
[security_incidents]
external_type = kvstore
collection = security_incidents
fields_list = _key, incident_id, alert_id, alert_name, severity, status, assigned_to, created_time, updated_time, src_entity, mitre_technique_id, mitre_tactic, description, notes
```

#### Step 3: Restart Splunk

```bash
$SPLUNK_HOME/bin/splunk restart
```

#### Step 4: Verify Collection Exists

```spl
| rest /services/data/transforms/lookups 
| search title="security_incidents"
| table title, type, eai:acl.app
```

---

### Stage 2: SOC Users Lookup

#### Step 1: Create SOC Users CSV

**File:** `$SPLUNK_HOME/etc/apps/DC_cyber_secmon/lookups/soc_users.csv`

```csv
username,full_name,email,role,team,status
john.smith,John Smith,john.smith@company.com,SOC Analyst L1,Security Operations,active
jane.doe,Jane Doe,jane.doe@company.com,SOC Analyst L2,Security Operations,active
mike.johnson,Mike Johnson,mike.johnson@company.com,SOC Lead,Security Operations,active
unassigned,Unassigned,noreply@company.com,N/A,N/A,active
```

**Customize with your actual SOC team members!**

#### Step 2: Create Lookup Definition

**Via Splunk Web:**
1. Settings → Lookups → Lookup definitions
2. Click "New Lookup Definition"
3. Settings:
   - Destination app: DC_cyber_secmon
   - Name: soc_users
   - Type: File-based
   - Lookup file: soc_users.csv
4. Save

**Or via transforms.conf:**

```ini
[soc_users]
filename = soc_users.csv
```

#### Step 3: Test Lookup

```spl
| inputlookup soc_users.csv
| table username, full_name, role, status
```

---

### Stage 3: Dashboard Setup

#### Step 1: Create Dashboard

1. In Splunk Web: Settings → User Interface → Dashboards
2. Click "Create New Dashboard"
3. Settings:
   - Title: Security Incidents Dashboard
   - ID: incidents_dashboard
   - App: DC_cyber_secmon
   - Permissions: Shared in App
4. Save
5. Switch to "Source" mode
6. Replace XML with complete dashboard XML
7. **Important:** Ensure first line is:
   ```xml
   <form script="create_incident.js">
   ```

#### Step 2: Create JavaScript File

**File:** `$SPLUNK_HOME/etc/apps/DC_cyber_secmon/appserver/static/create_incident.js`

1. Create the `appserver/static/` directory if it doesn't exist:
   ```bash
   mkdir -p $SPLUNK_HOME/etc/apps/DC_cyber_secmon/appserver/static/
   ```

2. Create `create_incident.js` with the complete JavaScript code

3. Set permissions:
   ```bash
   chmod 644 $SPLUNK_HOME/etc/apps/DC_cyber_secmon/appserver/static/create_incident.js
   ```

#### Step 3: Restart Splunk

```bash
$SPLUNK_HOME/bin/splunk restart
```

#### Step 4: Clear Browser Cache

**Chrome/Edge (Mac):**
```
Cmd + Shift + R
```

**Safari (Mac):**
```
Cmd + Option + E (clear cache)
Cmd + R (refresh)
```

**Firefox (Mac):**
```
Cmd + Shift + R
```

#### Step 5: Verify Installation

1. Open incidents dashboard
2. Press F12 (Developer Console)
3. Look for console messages:
   ```
   Create Incident JavaScript loaded successfully
   Create Incident event handler registered
   Update Incident event handler registered
   Delete Incident event handler registered
   ```

If you see all messages, installation is complete! ✅

---

## User Guide

### Dashboard Overview

When you open the Security Incidents Dashboard, you'll see:

#### Top Section: Filters
- **Status Filter**: All Statuses, Open, Investigating, Closed
- **Severity Filter**: All Severities, Critical, High, Medium, Low
- **Assigned To Filter**: All Users, Unassigned, or specific analyst

#### Summary Statistics (4 Panels)
- **Total Incidents**: Count of all incidents matching filters
- **Open Incidents**: Count of incidents needing attention
- **Investigating**: Count of incidents being worked
- **Unassigned**: Count of incidents needing assignment

#### Visualizations (3 Charts)
- **Incidents by Status**: Pie chart showing status distribution
- **Incidents by Severity**: Bar chart showing severity breakdown
- **Incidents by MITRE Tactic**: Bar chart showing attack tactics

#### Incident Details Table
- Comprehensive table showing all incident fields
- Color-coded by severity and status
- Sortable columns
- Row numbers for reference

#### Assignment Summary
- Shows workload per analyst
- Breaks down by status (open, investigating, closed)
- Lists severity distribution

#### Recent Activity
- Last 10 updated incidents
- Quick view of recent changes

---

### Creating an Incident

#### Step 1: Navigate to "Create New Incident from Notable Alert"

Scroll to the bottom of the dashboard.

#### Step 2: Select Alert

1. Click the **"Select Alert to Create Incident"** dropdown
2. You'll see alerts from the last 24 hours in format:
   ```
   END_ALT-001 - Suspicious Registry Modification (WORKSTATION01) - 2024-11-01 10:30
   ```
3. Select the alert you want to convert to an incident

#### Step 3: Review Alert Details

A table appears showing:
- Alert ID, Name, Severity
- Source Entity (affected host/user)
- MITRE Technique and Tactic
- Additional context

#### Step 4: Fill Incident Form

The form appears with three fields:

**Incident Description:**
- Pre-filled with: "Investigate alert: [Alert ID]"
- Edit as needed to add context

**Assign To:**
- Dropdown populated from SOC users lookup
- Select analyst to assign
- Default: "unassigned"

**Initial Notes (Optional):**
- Add any initial investigation notes
- Can be left blank

#### Step 5: Create Incident

1. Click **"Create Incident"** button
2. Button changes to "Creating..." (disabled during process)
3. Success popup appears: "Incident INC-xxxxx created successfully!"
4. Page reloads automatically after 1 second
5. New incident appears in Incident Details table

#### Generated Incident Details:
- **Incident ID**: Auto-generated (INC-timestamp)
- **Status**: Automatically set to "open"
- **Created Time**: Current timestamp
- **Updated Time**: Same as created time
- **All alert fields**: Automatically copied

---

### Updating an Incident

#### Step 1: Navigate to "Update Existing Incident"

Scroll to the update section of the dashboard.

#### Step 2: Select Incident

1. Click the **"Select Incident to Update"** dropdown
2. You'll see incidents in format:
   ```
   INC-1730467890123 - Suspicious Registry Modification (Status: open, Assigned: unassigned)
   ```
3. Select the incident you want to update

#### Step 3: Review Current Details

A table appears showing:
- Incident ID
- Alert Name
- Current Status
- Currently Assigned To
- Severity
- Created and Last Updated times
- Description

#### Step 4: Set New Values

**New Status:**
- Dropdown with options:
  - Open (initial state)
  - Investigating (actively working)
  - Closed (resolved)

**Assign To:**
- Dropdown populated from SOC users lookup
- Select new analyst
- Or select "unassigned" to remove assignment

#### Step 5: Update Incident

1. Click **"Update Incident"** button
2. Button changes to "Updating..." (disabled during process)
3. Success popup appears: "Incident INC-xxxxx updated successfully!"
4. Shows new status and assignment
5. Page reloads automatically after 1 second
6. Updated incident shows new values and updated timestamp

---

### Deleting an Incident

#### Step 1: Navigate to "Delete Incident"

Scroll to the delete section (if implemented).

#### Step 2: Select Incident

Choose the incident to delete from dropdown.

#### Step 3: Confirm Deletion

1. Click **"Delete Incident"** button
2. Confirm in popup dialog
3. Incident removed from KVStore
4. Page reloads

**Note:** Only delete closed incidents. There's no undo!

---

### Incident Workflow Best Practices

#### Standard Incident Lifecycle

```
┌──────────┐     ┌──────────────┐     ┌────────┐
│  Alert   │ --> │   Incident   │ --> │ Closed │
│ Created  │     │              │     │        │
└──────────┘     └──────────────┘     └────────┘
                        │
                        ▼
                 ┌──────────────┐
                 │ Investigation│
                 │  In Progress │
                 └──────────────┘
```

#### Recommended Workflow

1. **Alert Triggers** → Notable alert created in `notable` index

2. **Initial Triage** (Status: Open)
   - Analyst reviews alert in dashboard
   - Creates incident from alert
   - Adds initial description
   - Assigns to self or leaves unassigned

3. **Investigation** (Status: Investigating)
   - Analyst claims incident (updates assignment)
   - Changes status to "investigating"
   - Adds investigation notes
   - Gathers evidence

4. **Resolution** (Status: Closed)
   - Investigation complete
   - Changes status to "closed"
   - Documents resolution in notes

#### Status Definitions

| Status | Meaning | Who | Actions |
|--------|---------|-----|---------|
| **Open** | New incident, needs triage | Unassigned or L1 | Review alert, determine severity, assign |
| **Investigating** | Active investigation | Assigned analyst | Gather evidence, correlate events, document findings |
| **Closed** | Resolved or false positive | Assigned analyst | Document outcome, lessons learned |

#### Assignment Guidelines

- **Unassigned**: Incidents in queue awaiting assignment
- **L1 Analyst**: Initial triage, low/medium severity
- **L2 Analyst**: Complex investigations, high severity
- **SOC Lead**: Critical incidents, escalations
- **Incident Responder**: Active breaches, forensics

---

## Technical Details

### KVStore Operations

#### Create Operation

**JavaScript Function:** `create_incident_btn` click handler

**Process:**
1. Fetch alert data from `notable` index
2. Generate unique incident ID: `INC-` + timestamp
3. Combine alert fields + user input
4. Write to KVStore via `outputlookup append=true`

**SPL Query:**
```spl
index=notable alert_id="END_ALT-001" earliest=-24h latest=now 
| head 1 
| eval incident_id="INC-1730467890123"
| eval description="User entered description"
| eval assigned_to="john.smith"
| eval notes="Optional notes"
| eval status="open"
| eval created_time=now()
| eval updated_time=now()
| table incident_id, alert_id, alert_name, severity, status, assigned_to, created_time, updated_time, src_entity, mitre_technique_id, mitre_tactic, description, notes
| outputlookup append=true security_incidents
```

#### Update Operation

**JavaScript Function:** `update_incident_btn` click handler

**Process:**
1. Read all incidents from KVStore
2. Use conditional `eval` to update matching incident
3. Update `updated_time` field
4. Write entire collection back to KVStore

**SPL Query:**
```spl
| inputlookup security_incidents
| eval status=if(incident_id="INC-1730467890123", "investigating", status)
| eval assigned_to=if(incident_id="INC-1730467890123", "jane.doe", assigned_to)
| eval updated_time=if(incident_id="INC-1730467890123", now(), updated_time)
| outputlookup security_incidents
```

#### Delete Operation

**JavaScript Function:** `delete_incident_btn` click handler

**Process:**
1. Read all incidents from KVStore
2. Filter out the incident to delete
3. Write remaining incidents back to KVStore

**SPL Query:**
```spl
| inputlookup security_incidents
| where incident_id!="INC-1730467890123"
| outputlookup security_incidents
```

#### Read Operation

**Dashboard Panels:** Use `inputlookup` to query KVStore

**SPL Query:**
```spl
| inputlookup security_incidents
| search status="open" severity="high"
| eval created_time=strftime(created_time, "%Y-%m-%d %H:%M:%S")
| table incident_id, alert_name, status, assigned_to, created_time
```

---

### JavaScript Architecture

#### Module Structure

```javascript
require([
    "splunkjs/mvc",
    "splunkjs/mvc/searchmanager",
    "jquery",
    "splunkjs/mvc/simplexml/ready!"
], function(mvc, SearchManager, $) {
    // Code here runs after Splunk MVC loads
    
    var tokens = mvc.Components.get("default");
    
    $(document).ready(function() {
        // DOM manipulation and event handlers
        
        $(document).on("click", "#create_incident_btn", function() {
            // Create incident logic
        });
        
        $(document).on("click", "#update_incident_btn", function() {
            // Update incident logic
        });
    });
});
```

#### Token Management

**Get Token Values:**
```javascript
var alert_id = tokens.get("selected_alert_id");
var description = tokens.get("incident_description");
```

**Set Token Values:**
```javascript
tokens.set("selected_alert_id", "");
```

**Get HTML Input Values:**
```javascript
var incident_id = $("#update_id_input").val();
var new_status = $("select[token='new_status']").val();
```

#### Search Execution

```javascript
var searchManager = new SearchManager({
    id: "unique_search_id_" + Date.now(),
    earliest_time: "-24h",
    latest_time: "now",
    search: "index=notable | stats count",
    autostart: true
});

searchManager.on("search:done", function(properties) {
    console.log("Search completed successfully");
});

searchManager.on("search:error", function(properties) {
    console.error("Search error:", properties);
});
```

---

### Dashboard XML Structure

#### Form Declaration

```xml
<form script="create_incident.js">
  <label>Security Incidents Dashboard</label>
  <description>Dashboard description</description>
```

**Important:** The `script="create_incident.js"` attribute loads the JavaScript file.

#### Input Types

**Dropdown (with search):**
```xml
<input type="dropdown" token="token_name" searchWhenChanged="true">
  <label>Label</label>
  <search>
    <query>| inputlookup lookup_file | table field</query>
  </search>
  <fieldForLabel>display_field</fieldForLabel>
  <fieldForValue>value_field</fieldForValue>
  <default>default_value</default>
</input>
```

**Text Input:**
```xml
<input type="text" token="token_name">
  <label>Label</label>
  <default>default value</default>
</input>
```

**HTML Button:**
```xml
<html>
  <button class="btn btn-primary" id="button_id">Button Text</button>
</html>
```

#### Conditional Panels

Panels can be shown/hidden based on token values:

```xml
<row depends="$token_name$">
  <panel>
    <!-- Only visible when token_name has a value -->
  </panel>
</row>
```

---

## Troubleshooting

### Common Issues and Solutions

#### Issue 1: JavaScript Not Loading

**Symptoms:**
- Console doesn't show "JavaScript loaded successfully"
- Buttons don't work
- No console errors

**Solutions:**

1. **Verify file location:**
   ```bash
   ls -la $SPLUNK_HOME/etc/apps/DC_cyber_secmon/appserver/static/create_incident.js
   ```
   File should exist with read permissions (644).

2. **Check dashboard references script:**
   ```bash
   head -5 $SPLUNK_HOME/etc/apps/DC_cyber_secmon/local/data/ui/views/incidents_dashboard.xml
   ```
   First line should be: `<form script="create_incident.js">`

3. **Restart Splunk:**
   ```bash
   $SPLUNK_HOME/bin/splunk restart
   ```

4. **Clear browser cache:**
   Hard refresh (Cmd+Shift+R on Mac, Ctrl+Shift+R on Windows)

5. **Check Splunk logs:**
   ```bash
   tail -f $SPLUNK_HOME/var/log/splunk/web_service.log
   ```
   Look for JavaScript errors.

---

#### Issue 2: Create Incident Button Does Nothing

**Symptoms:**
- Button clicks but nothing happens
- No console logs
- No error messages

**Solutions:**

1. **Check browser console (F12):**
   Look for JavaScript errors.

2. **Verify button ID matches:**
   In XML: `id="create_incident_btn"`
   In JS: `$("#create_incident_btn")`

3. **Test if jQuery works:**
   In console:
   ```javascript
   $("#create_incident_btn").length
   ```
   Should return `1` if button exists.

4. **Check if alert is selected:**
   In console:
   ```javascript
   require(["splunkjs/mvc"], function(mvc) {
       var tokens = mvc.Components.get("default");
       console.log(tokens.get("selected_alert_id"));
   });
   ```
   Should show the alert ID.

---

#### Issue 3: Incident Not Created in KVStore

**Symptoms:**
- Success popup appears
- Page reloads
- Incident not in table

**Solutions:**

1. **Verify KVStore collection exists:**
   ```spl
   | rest /services/data/transforms/lookups 
   | search title="security_incidents"
   ```

2. **Check KVStore permissions:**
   ```spl
   | rest /servicesNS/nobody/DC_cyber_secmon/storage/collections/config/security_incidents
   | table title, eai:acl.*
   ```

3. **Test manual write:**
   ```spl
   | makeresults 
   | eval incident_id="TEST-001"
   | eval status="open"
   | eval created_time=now()
   | outputlookup append=true security_incidents
   ```

4. **Check for search errors:**
   ```spl
   index=_internal source=*scheduler.log* ERROR "security_incidents"
   ```

---

#### Issue 4: Update Doesn't Change Incident

**Symptoms:**
- Update button works
- Success message appears
- Incident values unchanged

**Solutions:**

1. **Verify incident ID is correct:**
   Check console logs for the incident_id being updated.

2. **Test update manually:**
   ```spl
   | inputlookup security_incidents
   | eval status=if(incident_id="INC-123", "closed", status)
   | outputlookup security_incidents
   ```

3. **Check if incident exists:**
   ```spl
   | inputlookup security_incidents
   | search incident_id="INC-123"
   ```

4. **Verify updated_time changed:**
   If status didn't change but updated_time did, the update logic works but conditions might be wrong.

---

#### Issue 5: Dropdown Empty (No Alerts/Incidents)

**Symptoms:**
- Alert dropdown shows no results
- Incident dropdown shows no results

**Solutions for Alert Dropdown:**

1. **Check notable index has data:**
   ```spl
   index=notable earliest=-24h | stats count
   ```

2. **Run one of your alerts manually** to generate test data.

3. **Check alert_id field exists:**
   ```spl
   index=notable earliest=-24h | head 1 | table alert_id, alert_name
   ```

**Solutions for Incident Dropdown:**

1. **Check incidents exist:**
   ```spl
   | inputlookup security_incidents | stats count
   ```

2. **Create a test incident** using the create form or manual SPL.

---

#### Issue 6: Page Doesn't Reload After Operation

**Symptoms:**
- Success popup appears
- Page doesn't reload
- Have to manually refresh

**Solutions:**

1. **Check JavaScript console for errors** during reload.

2. **Verify `location.reload()` is called:**
   In JS code, check for:
   ```javascript
   setTimeout(function() {
       location.reload();
   }, 1000);
   ```

3. **Browser might block reload** - check browser settings.

---

### Debug Mode

To enable verbose logging, add this to the top of your JavaScript file:

```javascript
var DEBUG = true;

function debugLog(message, data) {
    if (DEBUG) {
        console.log("[DEBUG] " + message, data || "");
    }
}
```

Then use throughout:
```javascript
debugLog("Alert ID:", alert_id);
debugLog("Generated Incident ID:", incident_id);
```

---

## Best Practices

### Incident Management

#### 1. Regular Triage

- Review open incidents daily
- Assign unassigned incidents within 1 hour
- Escalate high/critical incidents immediately

#### 2. Status Updates

- Update status when work begins (open → investigating)
- Add notes during investigation
- Close incidents promptly when resolved

#### 3. Assignment Strategy

- Balance workload across team
- Assign based on analyst expertise
- Re-assign if analyst unavailable

#### 4. Documentation

- Add meaningful descriptions when creating incidents
- Update notes with investigation findings
- Document resolution details before closing

#### 5. Incident Retention

- Keep closed incidents for compliance period
- Archive old incidents periodically
- Export to SIEM for long-term storage

---

### System Maintenance

#### 1. Regular Backups

Backup KVStore collection weekly:

```bash
$SPLUNK_HOME/bin/splunk dump kvstore -app DC_cyber_secmon -collection security_incidents > incidents_backup_$(date +%Y%m%d).json
```

Restore if needed:
```bash
$SPLUNK_HOME/bin/splunk restore kvstore -app DC_cyber_secmon -collection security_incidents -file incidents_backup_20241101.json
```

#### 2. Monitor Collection Size

```spl
| rest /servicesNS/nobody/DC_cyber_secmon/storage/collections/config/security_incidents
| table title, size
```

If collection grows too large, archive old closed incidents.

#### 3. Update SOC Users Regularly

Keep `soc_users.csv` current:
- Add new team members
- Mark departed analysts as `status=inactive`
- Update roles and contact info

#### 4. Review Dashboard Performance

Monitor search execution times:

```spl
index=_internal source=*scheduler.log* savedsearch_name="*incident*"
| stats avg(run_time) as avg_runtime by savedsearch_name
```

Optimize slow searches if needed.

#### 5. Security Considerations

- Restrict dashboard access to SOC team
- Audit KVStore access:
  ```spl
  index=_audit action="kvstore_*" object="security_incidents"
  | table _time, user, action, object
  ```
- Review permissions quarterly

---

### Performance Optimization

#### 1. Index Acceleration

Ensure KVStore collection is accelerated (already configured):

```ini
accelerated_fields.incident_lookup = {"incident_id": 1, "status": 1, "severity": 1, "assigned_to": 1}
```

#### 2. Limit Dashboard Time Ranges

- Use appropriate time ranges in searches
- Avoid `earliest=0` (searches all time)
- Default to last 24h or 7d

#### 3. Efficient Filtering

Use indexed fields in searches:
```spl
| inputlookup security_incidents
| search status="open"  ← Fast (indexed)
```

Instead of:
```spl
| inputlookup security_incidents
| where status="open"  ← Slower (post-processing)
```

#### 4. Deduplication

In alert dropdown, deduplicate to reduce results:
```spl
| dedup alert_id, src_entity
```

#### 5. Minimize Real-time Searches

Use scheduled searches for dashboards instead of real-time where possible.

---

### Workflow Automation Ideas

#### 1. Auto-Assignment Rules

Create scheduled search to auto-assign incidents:

```spl
| inputlookup security_incidents
| where status="open" AND assigned_to="unassigned"
| eval assigned_to=case(
    severity="critical", "soc_lead",
    severity="high", "senior_analyst",
    1=1, "junior_analyst"
)
| outputlookup security_incidents
```

#### 2. SLA Monitoring

Alert on incidents open too long:

```spl
| inputlookup security_incidents
| where status!="closed"
| eval age_hours=round((now()-created_time)/3600, 1)
| where age_hours > 24
| table incident_id, alert_name, status, assigned_to, age_hours
```

#### 3. Daily Summary Email

Send daily incident summary to SOC lead:

```spl
| inputlookup security_incidents
| stats
