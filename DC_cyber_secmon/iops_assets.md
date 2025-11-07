## Overview

The assets lookup is your source of truth for all IT assets in your environment. It enables:
- ✅ Tracking which hosts should be reporting
- ✅ Identifying missing/offline systems
- ✅ Filtering out expected downtime (maintenance windows)
- ✅ Prioritizing alerts based on asset criticality
- ✅ Compliance reporting (PCI, GDPR, etc.)

---

## Asset Lookup Fields Explained

### Core Identity Fields

| Field | Description | Example | Required |
|-------|-------------|---------|----------|
| `asset` | Hostname/Asset name | WORKSTATION01 | ✅ Yes |
| `ip` | IP address | 192.168.1.100 | ✅ Yes |
| `mac` | MAC address | 00:11:22:33:44:55 | No |
| `dns` | Fully qualified domain name | workstation01.corp.local | ✅ Yes |

**Note:** Use "DHCP" for IP if dynamically assigned

---

### Ownership & Organization

| Field | Description | Example | Required |
|-------|-------------|---------|----------|
| `owner` | Primary responsible person | john.smith | ✅ Yes |
| `bunit` | Business unit | IT, Finance, Engineering | ✅ Yes |
| `location` | Physical or logical location | Office-Floor2, DataCenter-RackA1 | ✅ Yes |

---

### Classification Fields

| Field | Description | Values | Required |
|-------|-------------|--------|----------|
| `category` | Asset type | workstation, server, network, laptop | ✅ Yes |
| `priority` | Business criticality | critical, high, medium, low | ✅ Yes |
| `os` | Operating system | Windows 10, Ubuntu 20.04, FortiOS | ✅ Yes |

**Priority Definitions:**
- **Critical**: Revenue-impacting, public-facing, or PCI systems
- **High**: Core business systems, production databases
- **Medium**: Standard workstations, development systems
- **Low**: Test systems, decommissioned assets

---

### Monitoring & Compliance

| Field | Description | Values | Purpose |
|-------|-------------|--------|---------|
| `is_expected` | Should report regularly | true, false | Filter decommissioned assets |
| `pci_domain` | In PCI compliance scope | true, false | Compliance reporting |
| `requires_av` | Antivirus required | true, false | Security posture checks |

---

### Maintenance & Operations

| Field | Description | Example | Purpose |
|-------|-------------|---------|---------|
| `maintenance_window` | Scheduled downtime | Sunday 02:00-04:00 UTC | Filter false alerts |
| `notes` | Additional context | Patch Tuesday 2nd Wed | Documentation |

**Maintenance Window Formats:**
- Specific: "Sunday 02:00-04:00 UTC"
- Recurring: "Patch Tuesday 2nd Wed of month"
- Flexible: "Anytime", "Emergency only"
- None: "None" (for always-on systems)

---

## Installation Steps

### Step 1: Create the CSV File

1. Navigate to lookups directory:
   ```bash
   cd $SPLUNK_HOME/etc/apps/DC_cyber_secmon/lookups/
   ```

2. Create `assets.csv`:
   ```bash
   vi assets.csv
   ```

3. Paste the sample data from Artifact 1

4. **Customize with your actual assets!**
   - Replace sample hosts with real inventory
   - Update IP addresses to match your network
   - Set accurate owners and business units
   - Define maintenance windows

5. Save the file

### Step 2: Create Lookup Definition

**Via Splunk Web (Recommended):**

1. Go to **Settings → Lookups → Lookup definitions**
2. Click **"New Lookup Definition"**
3. Fill in:
   - **Destination app:** DC_cyber_secmon
   - **Name:** assets
   - **Type:** File-based
   - **Lookup file:** assets.csv
4. Click **"Save"**

**Or via transforms.conf:**

Add to `$SPLUNK_HOME/etc/apps/DC_cyber_secmon/local/transforms.conf`:

```ini
[assets]
filename = assets.csv
```

Then restart Splunk:
```bash
$SPLUNK_HOME/bin/splunk restart
```

### Step 3: Test the Lookup

```spl
| inputlookup assets.csv
| table asset, ip, owner, category, priority, is_expected, maintenance_window
```

You should see all your assets listed!

---

## Populating Your Assets Lookup

### Option 1: Manual Entry (Small Environments)

For <50 assets, manual CSV editing is fine:
1. List all assets in a spreadsheet
2. Fill in required fields
3. Export as CSV
4. Upload to Splunk

### Option 2: Export from Asset Management System

If you have ServiceNow, Jira Assets, or similar:
1. Export asset inventory
2. Map fields to match CSV format
3. Import into Splunk

### Option 3: Auto-Discovery from Splunk Data

Build asset list from observed data:

```spl
index=* earliest=-30d latest=now
| stats count by host
| eval asset=host
| eval is_expected="true"
| eval priority="medium"
| eval category="unknown"
| table asset, is_expected, priority, category
| outputlookup assets.csv
```

Then manually fill in missing details.

---

## Maintaining the Asset Lookup

### Regular Updates (Recommended: Weekly)

**Add New Assets:**
- New servers provisioned
- New employee workstations
- New network devices

**Update Existing Assets:**
- Ownership changes
- IP address changes
- Priority adjustments
- Maintenance window updates

**Remove Decommissioned Assets:**
- Don't delete immediately - set `is_expected="false"`
- Keep for historical tracking
- Remove after 90 days

### Version Control

Keep backups before major changes:

```bash
cp assets.csv assets.csv.backup-$(date +%Y%m%d)
```

### Validation

Test after updates:

```spl
| inputlookup assets.csv
| stats count by is_expected, priority, category
```

Ensure counts make sense.

---

## Asset Categories Guide

### Workstation
- Desktop computers
- Standard user laptops
- Thin clients

**Typical Settings:**
- Priority: medium
- Requires AV: true
- Maintenance: Patch Tuesday

---

### Server
- Physical servers
- Virtual machines
- Application servers
- Database servers

**Typical Settings:**
- Priority: critical or high
- Requires AV: true (except Linux in some cases)
- Maintenance: Scheduled windows

---

### Network
- Firewalls
- Routers
- Switches
- Load balancers
- VPN gateways

**Typical Settings:**
- Priority: critical
- Requires AV: false
- Maintenance: Emergency only

---

### Laptop
- Mobile/remote devices
- May have DHCP/dynamic IPs
- Intermittent connectivity expected

**Typical Settings:**
- Priority: medium
- Requires AV: true
- Maintenance: Flexible

---

## Priority Assignment Guidelines

### Critical
**Criteria:**
- Public-facing services
- Revenue-generating systems
- PCI/compliance-scoped
- Single point of failure

**Examples:**
- Production web servers
- Payment processing systems
- Primary firewalls
- Core network infrastructure

---

### High
**Criteria:**
- Core business functions
- Important but not customer-facing
- Redundant systems

**Examples:**
- Production databases
- Internal application servers
- Authentication systems (AD, LDAP)
- File servers

---

### Medium
**Criteria:**
- Standard operational systems
- Non-critical business functions
- End-user devices

**Examples:**
- Employee workstations
- Development servers
- Standard laptops
- Printers

---

### Low
**Criteria:**
- Test/development
- Non-production
- Decommissioned

**Examples:**
- QA/test systems
- Lab equipment
- Staging environments
- Systems being retired

---

## Common Use Cases

### Use Case 1: Find All Critical Assets

```spl
| inputlookup assets.csv
| where priority="critical" AND is_expected="true"
| table asset, ip, owner, category, location
```

### Use Case 2: Assets in Maintenance Window

```spl
| inputlookup assets.csv
| where isnotnull(maintenance_window) AND maintenance_window!="None"
| table asset, maintenance_window, owner, priority
```

### Use Case 3: PCI Scope Assets

```spl
| inputlookup assets.csv
| where pci_domain="true" AND is_expected="true"
| table asset, ip, category, owner, location
```

### Use Case 4: Missing Antivirus Required

```spl
| inputlookup assets.csv
| where requires_av="true" AND is_expected="true"
| table asset, owner, os, category
```

---


