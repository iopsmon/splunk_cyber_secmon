# Guide: SOC Maturity Assessment Dashboard

## 1. Overview

This document explains how the **SOC Maturity Assessment Dashboard** works. The dashboard is designed to provide a clear, visual representation of your Security Operations Center (SOC) maturity based on the data in the `soc_maturity_assessment.csv` lookup file.

Its primary purpose is to:
-   Visualize the current state of your SOC's capabilities.
-   Calculate a weighted maturity score.
-   Highlight critical gaps and risk areas.
-   Provide a prioritized, actionable list of items to address.

---

## 2. The Core Concept: Lookup-Driven Visualization

The entire dashboard is powered by a single CSV file: `soc_maturity_assessment.csv`. It works on a simple principle:

1.  **Data Source**: The dashboard reads the contents of the `soc_maturity_assessment.csv` lookup file at search time using the `| inputlookup soc_maturity_assessment.csv` command.
2.  **Data Processing**: Splunk searches then process the rows from the CSV to calculate scores, count statuses, and aggregate data by category.
3.  **Visualization**: The results of these searches are displayed in various panels, such as single value KPIs, charts, and tables.

This means **the dashboard is a direct reflection of the data in the CSV**. To update the dashboard, you simply update the CSV file.

---

## 3. Understanding the Key Fields

The logic of the dashboard relies on two critical fields in the `soc_maturity_assessment.csv` file: `status` and `weight`.

| Field    | Description                                                                                                                               | Example Values |
| :------- | :---------------------------------------------------------------------------------------------------------------------------------------- | :------------- |
| `status` | Indicates whether an assessment item is completed or not. This is the primary driver for all calculations.                                 | `yes`, `no`    |
| `weight` | Represents the **importance or criticality** of an item, typically on a scale of 1 to 10. A higher weight means the item has a greater impact on your overall security posture. | `10`, `9`, `8` |

**Crucially, `weight` does not mean completion.** A weight of `10` signifies a *critically important* item, not a completed one. The combination of a `no` status and a high `weight` represents a top-priority gap that needs immediate attention.

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
    |  inputlookup iops_soc_assessment
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
    | inputlookup | inputlookup iops_soc_assessment
    | where status="no"
    | sort - weight
    ```

---

## 5. How to Use and Update the Dashboard

### Daily/Weekly Workflow

1.  **Check the KPIs**: Start with the "Overall Maturity Score" and "Critical Gaps" to get a quick sense of your current posture.
2.  **Identify Weak Areas**: Look at the "Maturity Score by Category" table to see which domains are lagging.
3.  **Create an Action Plan**: Use the **"Prioritized Gaps"** table as your to-do list. The items at the top are your highest priorities.

### Updating Your Progress

The dashboard will update automatically as you update the `soc_maturity_assessment.csv` file.

**To mark an item as complete:**

1.  Open the `soc_maturity_assessment.csv` file (in the Lookup Editor in Splunk or your version control system).
2.  Find the row corresponding to the task you've completed.
3.  Change the value in the `status` column from **`no`** to **`yes`**.
4.  Add any relevant information to the `notes` column.
5.  Save the file.

The next time the dashboard is refreshed, the scores and charts will reflect your changes. The completed item will disappear from the "Prioritized Gaps" table, and your "Overall Maturity Score" will increase.


