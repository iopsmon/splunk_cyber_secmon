# Guide: SOC Maturity Assessment Dashboard

## 1. Overview

This document explains how the **SOC Maturity Assessment Dashboard** works. The dashboard is designed to provide a clear, visual representation of your Security Operations Center (SOC) maturity based on the data in the `iops_soc_assessment.csv` lookup file.

Its primary purpose is to:
-   Visualize the current state of your SOC's capabilities.
-   Calculate a weighted maturity score.
-   Highlight critical gaps and risk areas.
-   Provide a prioritized, actionable list of items to address.
-   **Show project delivery impact** with timeline estimates, phased roadmaps, and risk assessments.

---

## 2. The Core Concept: Lookup-Driven Visualization

The entire dashboard is powered by a single CSV file: `iops_soc_assessment.csv`. It works on a simple principle:

1.  **Data Source**: The dashboard reads the contents of the `iops_soc_assessment.csv` lookup file at search time using the `| inputlookup iops_soc_assessment` command.
2.  **Data Processing**: Splunk searches then process the rows from the CSV to calculate scores, count statuses, and aggregate data by category.
3.  **Visualization**: The results of these searches are displayed in various panels, such as single value KPIs, charts, and tables.

This means **the dashboard is a direct reflection of the data in the CSV**. To update the dashboard, you simply update the CSV file.

---

## 3. Understanding the Key Fields

The logic of the dashboard relies on several critical fields in the `iops_soc_assessment.csv` file:

### Core Assessment Fields

| Field    | Description                                                                                                                               | Example Values |
| :------- | :---------------------------------------------------------------------------------------------------------------------------------------- | :------------- |
| `status` | Indicates whether an assessment item is completed or not. This is the primary driver for all calculations.                                 | `yes`, `no`    |
| `weight` | Represents the **importance or criticality** of an item, typically on a scale of 1 to 10. A higher weight means the item has a greater impact on your overall security posture. | `10`, `9`, `8` |
| `category` | Groups assessment items into logical domains (Foundation, Planning, Governance, Technical, People). | `Technical`, `Planning` |
| `question` | The specific assessment item or capability being evaluated. | `All Critical Data Sources Ingested` |
| `notes` | Additional context or comments about the item. | `Only 40% of sources sending logs - CRITICAL` |

**Crucially, `weight` does not mean completion.** A weight of `10` signifies a *critically important* item, not a completed one. The combination of a `no` status and a high `weight` represents a top-priority gap that needs immediate attention.

### Project Delivery Fields

These fields were added to support project planning and risk assessment:

| Field    | Description                                                                                                                               | Example Values |
| :------- | :---------------------------------------------------------------------------------------------------------------------------------------- | :------------- |
| `effort_days` | Estimated number of days required to implement or complete this item. | `5`, `30`, `90` |
| `phase` | The recommended implementation phase based on priority and effort. | `Phase 1: Quick Wins (0-3 months)`, `Phase 2: Medium-term (3-6 months)`, `Phase 3: Long-term (6-12 months)` |
| `risk_if_not_addressed` | A description of the security risk or business impact if this gap remains unaddressed. | `Unable to detect common attack patterns and security threats in real-time` |

These fields enable the dashboard to show:
- **Implementation timelines** - How long it will take to address gaps
- **Phased roadmaps** - Which items to tackle first, second, and third
- **Risk visibility** - What's at stake if gaps aren't addressed

---

## 4. Dashboard Panels Explained

The dashboard is organized into rows, each serving a specific purpose.

### Row 1: High-Level KPIs

These panels give you an immediate, at-a-glance summary of your SOC's health.

#### **Overall Maturity Score**
-   **What it shows**: A weighted percentage score representing your overall maturity.
-   **How it's calculated**: It's not just a simple count of "yes" vs. "no". It uses the weights to provide a more accurate score.
    ```spl
    (Sum of weights for all "yes" items) / (Total sum of all weights) * 100
    ```
-   **SPL Logic**:
    ```splunk
    | inputlookup iops_soc_assessment
    | stats sum(eval(if(status="yes", weight, 0))) as completed_weight, sum(weight) as total_weight
    | eval maturity_score=round((completed_weight/total_weight)*100, 0)
    ```

#### **Critical Gaps (Weight 9+)**
-   **What it shows**: A count of the most critical, uncompleted items.
-   **How it's calculated**: It counts every row where the `status` is "no" AND the `weight` is 9 or 10.
-   **SPL Logic**:
    ```splunk
    | inputlookup iops_soc_assessment
    | where status="no" AND weight >= 9
    | stats count
    ```

### Row 2: Breakdown by Category

These panels help you identify which areas of your SOC are strong and which are weak.

#### **Maturity Score by Category**
-   **What it shows**: A table that applies the same weighted maturity score logic to each category (e.g., `Foundation`, `Planning`, `Technical`).
-   **Why it's useful**: It helps you pinpoint which specific domains require the most attention. For example, you might have a high score in "Governance" but a very low score in "Technical".

#### **Completion Status by Category**
-   **What it shows**: A bar chart visually comparing the number of `yes` and `no` items within each category.

### Row 3: Actionable Insights

This is the most important panel for driving action and improvements.

#### **Prioritized Gaps (Status = "no")**
-   **What it shows**: A table listing **only the items with a status of "no"**.
-   **How it's prioritized**: The table is automatically sorted by `weight` from highest to lowest. The item at the top is the most important gap you should work on next.
-   **SPL Logic**:
    ```splunk
    | inputlookup iops_soc_assessment
    | where status="no"
    | sort - weight
    ```

### Project Delivery Impact Section

This new section provides critical insights for project planning and customer communication.

#### **Implementation Timeline Summary**
-   **Total Effort Required**: Shows the sum of all `effort_days` for outstanding gaps.
-   **Phase Breakdown**: Three single-value panels showing effort required for each phase:
    - **Phase 1: Quick Wins (0-3 months)** - Low effort, high impact items
    - **Phase 2: Medium-term (3-6 months)** - Moderate complexity items
    - **Phase 3: Long-term (6-12 months)** - Complex, resource-intensive items

#### **Implementation Roadmap Charts**
-   **Gaps by Phase**: Bar chart showing the distribution of outstanding items across phases.
-   **Effort Distribution by Category**: Pie chart showing which categories require the most implementation effort.

#### **Phase-Specific Roadmap Tables**
Three detailed tables (one for each phase) showing:
-   Category
-   Task/Gap description
-   Effort estimate in days
-   Priority (weight)
-   Risk if not addressed

These tables serve as actionable project plans that can be:
- Shared with customers to set expectations
- Used to create project timelines
- Referenced for resource planning

#### **Critical Risks Panel**
-   **What it shows**: High-priority items (weight 9+) with their associated risks.
-   **Why it's useful**: Helps communicate the "so what?" to stakeholders. Shows not just what's missing, but what could happen if gaps remain.

---

## 5. How to Use and Update the Dashboard

### Daily/Weekly Workflow

1.  **Check the KPIs**: Start with the "Overall Maturity Score" and "Critical Gaps" to get a quick sense of your current posture.
2.  **Identify Weak Areas**: Look at the "Maturity Score by Category" table to see which domains are lagging.
3.  **Review Project Timeline**: Check the "Total Effort Required" and phase breakdowns to understand the scope of work ahead.
4.  **Create an Action Plan**: Use the **"Prioritized Gaps"** and phase-specific roadmap tables as your to-do list. The items at the top are your highest priorities.
5.  **Communicate Risks**: Use the "Critical Risks" panel when discussing security posture with leadership or customers.

### Updating Your Progress

The dashboard will update automatically as you update the `iops_soc_assessment.csv` file.

**To mark an item as complete:**

1.  Open the `iops_soc_assessment.csv` file (in the Lookup Editor in Splunk or your version control system).
2.  Find the row corresponding to the task you've completed.
3.  Change the value in the `status` column from **`no`** to **`yes`**.
4.  Update the `effort_days` to `0` (optional but recommended for tracking).
5.  Change the `phase` to `Completed` (optional).
6.  Update the `risk_if_not_addressed` to `N/A - Already implemented` (optional).
7.  Add any relevant information to the `notes` column.
8.  Save the file.

The next time the dashboard is refreshed, the scores and charts will reflect your changes. The completed item will disappear from the "Prioritized Gaps" table, your "Overall Maturity Score" will increase, and the project timeline will adjust accordingly.

### Adding New Assessment Items

To add new items to track:

1.  Open the `iops_soc_assessment.csv` file.
2.  Add a new row with all required fields:
    - `customer_name`: Name of the organization
    - `assessment_date`: Date of assessment (YYYY-MM-DD format)
    - `category`: Choose from existing categories or create a new one
    - `question`: Description of the capability or item
    - `status`: `yes` or `no`
    - `weight`: 1-10 (criticality)
    - `notes`: Any relevant context
    - `effort_days`: Estimated implementation time
    - `phase`: Recommended implementation phase
    - `risk_if_not_addressed`: Description of risk
3.  Save the file.

The new item will appear in all relevant dashboard panels.

---

## 6. Using the Dashboard for Customer Engagement

The enhanced dashboard is particularly valuable for customer conversations:

### Initial Assessment Meeting
-   Show the **Overall Maturity Score** to establish the baseline
-   Use **Maturity Score by Category** to identify strengths and weaknesses
-   Reference the **Critical Gaps** panel to emphasize urgent needs

### Project Proposal & Planning
-   Present the **Total Effort Required** to set scope expectations
-   Use **Phase Breakdown** to propose a phased implementation approach
-   Show **Phase-Specific Roadmap Tables** as the actual project plan
-   Reference **Effort Distribution by Category** to justify resource allocation

### Risk & Business Case Discussions
-   Use the **Critical Risks Panel** to articulate security risks in business terms
-   Show the connection between high-weight gaps and tangible business impacts
-   Demonstrate how addressing Phase 1 items provides immediate risk reduction

### Progress Reviews
-   Compare maturity scores over time to show improvement
-   Update the CSV as items are completed to show real-time progress
-   Use the reducing effort numbers to demonstrate value delivery

---

## 7. Best Practices

### For Assessment Accuracy
-   Review and update the assessment quarterly or after major changes
-   Involve multiple stakeholders when assigning `status` values
-   Be honest about gaps - the dashboard is only useful with accurate data

### For Project Planning
-   Be realistic with `effort_days` estimates - include testing and documentation time
-   Consider dependencies when assigning phases
-   Review risk descriptions with business stakeholders to ensure they resonate

### For Dashboard Maintenance
-   Keep the lookup file version-controlled
-   Document major changes in the `notes` field
-   Archive completed assessments for historical tracking

---

## 8. Troubleshooting

**Dashboard shows no data:**
-   Verify the lookup file `iops_soc_assessment.csv` exists in your app's lookups folder
-   Check that the file has the correct permissions
-   Ensure the CSV header row matches the expected field names

**Scores seem incorrect:**
-   Verify `weight` values are numbers (not text)
-   Check for typos in `status` field (must be exactly "yes" or "no")
-   Ensure no blank rows in the CSV

**New fields not showing:**
-   Confirm all new fields (`effort_days`, `phase`, `risk_if_not_addressed`) are present in the CSV header
-   Clear your browser cache and refresh the dashboard
-   Check Splunk's lookup table editor to verify the file structure

---

## 9. Summary

The SOC Maturity Assessment Dashboard provides a comprehensive view of your security operations maturity with built-in project planning capabilities. By maintaining accurate data in the `iops_soc_assessment.csv` lookup file, you get:

-   Real-time visibility into SOC capabilities
-   Weighted, priority-based gap analysis
-   Actionable project roadmaps with effort estimates
-   Risk-based justification for security investments
-   Progress tracking over time

Use this dashboard as a living tool that evolves with your SOC, helping you make data-driven decisions about where to invest time and resources for maximum security impact.
