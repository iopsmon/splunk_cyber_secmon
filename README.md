# Splunk Cyber Security Monitoring App (`DC_cyber_secmon`)

This repository contains the **Cyber Security Monitoring App**, a custom Splunk application designed for security detection development, threat analysis, and SOC (Security Operations Center) management.

It serves as a lightweight, focused platform for security analysts and detection engineers to build, test, and validate security use cases using real-world attack data from the Splunk Attack Data repository.

I developed this for myself as a way to develop use cases and skills.

![Cyber Security Monitoring Image](DC_cyber_secmon/static/secmon_dashboard.jpg) 

---

## 🚀 Getting Started

The best place to start is with the main application documentation, which provides a comprehensive overview of the app's architecture, purpose, and setup.

*   **➡️ Main App Overview**: Start here! Learn about the app's architecture, data flow, and core components.

---

## 📖 Detailed Documentation

This project is documented across several markdown files, each covering a specific component or dashboard within the app. Please refer to the links below for detailed information. All documentation is located within the `DC_cyber_secmon` directory.

### Use Case and Detection Engineering

*   **Use Case Development Tracker**
    *   Provides a detailed overview of all active security detection use cases, including SPL queries, MITRE ATT&CK mapping, and testing notes.

[Use Case Tracker](DC_cyber_secmon/iopsmon_use_case_tracker.md)


### Dashboards and Reporting

*   **Incidents Dashboard Overview**
    *   Explains the features and functionality of the main security incidents dashboard.

[Incident Overview](DC_cyber_secmon/iops_incident_overview.md)

*   **SOC Manager Report**
    *   A guide to the executive-level dashboard for monitoring SOC performance, team productivity, and SLA compliance.
 
[Management Report](DC_cyber_secmon/iops_soc_mgmt_report.md)

*   **SOC Maturity Assessment Dashboard**
    *   Documentation for the dashboard that visualizes SOC maturity based on a weighted assessment, helping to identify and prioritize gaps.

[Security Maturity Assessment](DC_cyber_secmon/iops_soc_maturity.md)

*   **Hosts Not Reporting Dashboard**
    *   An overview of the dashboard used to monitor asset health and identify systems that have stopped sending logs to Splunk.

[Hosts Reporting](DC_cyber_secmon/iops_hosts_reporting.md)

### Configuration

*   **Asset Configuration Guide**
    *   Explains how to configure the `assets.csv` lookup file, which is the source of truth for your IT asset inventory.

[IOPS Assets](DC_cyber_secmon/iops_assets.md)
   

---

This app is intended to complement enterprise security platforms by providing a dedicated environment for detection content development and validation.



