# Security Monitoring Baseline Framework

## Overview

The Security Monitoring Baseline is a comprehensive framework designed to help organizations identify, track, and measure their security monitoring coverage across their IT infrastructure. This baseline serves as a strategic tool for security teams to ensure they have adequate visibility into potential threats and can detect security incidents effectively.

---

## Why This is Important

### 1. **Visibility is the Foundation of Security**
You cannot protect what you cannot see. Without comprehensive monitoring coverage, attackers can operate undetected in your environment. This baseline ensures you have eyes on the critical areas where threats typically manifest.

### 2. **Risk-Based Prioritization**
Not all monitoring requirements are equal. This framework categorizes monitoring needs by:
- **Priority** (Critical, High, Medium, Low)
- **Compliance Requirements** (PCI-DSS, ISO27001, SOC2, GDPR, NIST)
- **Attack Tactics** (MITRE ATT&CK framework)

This allows you to focus resources on the most critical gaps first.

### 3. **Compliance and Audit Readiness**
Many regulatory frameworks mandate specific security monitoring capabilities. This baseline maps monitoring requirements to compliance frameworks, making it easier to:
- Demonstrate due diligence to auditors
- Identify compliance gaps before audits
- Maintain continuous compliance posture

### 4. **Measurable Security Posture**
The dashboard provides clear metrics on your monitoring coverage, allowing you to:
- Track improvement over time
- Report to leadership with concrete numbers
- Justify security investments with data

### 5. **Systematic Approach to Detection Engineering**
Rather than building detections reactively, this baseline provides a structured roadmap for developing comprehensive detection coverage across your environment.

---

## How This Should Be Used

### **IMPORTANT: This is a Post-Risk Assessment Tool**

⚠️ **This baseline is an example framework that should be customized AFTER completing your organization's risk assessment process.**

The 50 baseline requirements provided are industry best practices, but your organization's specific monitoring needs should be determined through:
1. Threat modeling exercises
2. Risk identification workshops
3. Asset criticality assessments
4. Compliance requirement analysis
5. Business impact assessments

---

## Implementation Workflow

### **Phase 1: Risk Assessment (Before Using This Tool)**

Before populating or customizing the baseline, complete these activities with your customer:

1. **Asset Identification**
   - Identify critical systems, data, and infrastructure
   - Document business processes and dependencies
   - Classify data sensitivity levels

2. **Threat Modeling**
   - Identify relevant threat actors for your industry
   - Document attack scenarios specific to your environment
   - Assess threat likelihood and potential impact

3. **Risk Identification**
   - Conduct vulnerability assessments
   - Review historical incidents
   - Identify control gaps
   - Document inherent risks

4. **Risk Treatment Planning**
   - Determine risk appetite and tolerance
   - Decide on risk treatment strategies (accept, mitigate, transfer, avoid)
   - Prioritize risks based on likelihood and impact

### **Phase 2: Baseline Customization**

Once the risk assessment is complete:

1. **Review the Example Baseline**
   - Evaluate the 50 provided monitoring requirements
   - Determine which are relevant to your environment
   - Identify any missing requirements specific to your risks

2. **Customize the Baseline**
   - Add organization-specific monitoring requirements
   - Remove requirements not applicable to your environment
   - Adjust priority levels based on your risk assessment findings
   - Update compliance framework mappings to match your obligations

3. **Populate Additional Fields**
   - Document specific data sources available in your environment
   - Map requirements to your specific SIEM/logging infrastructure
   - Add custom fields if needed (e.g., responsible team, target date)

### **Phase 3: Gap Analysis**

1. **Initial Coverage Assessment**
   - Review each baseline requirement
   - Determine current coverage status (Yes/No/Partial)
   - Update the `covered` field in the lookup

2. **Use the Dashboard**
   - Review overall coverage percentage
   - Identify critical and high-priority gaps
   - Analyze coverage by category (Endpoint, Network, Cloud, etc.)
   - Review compliance framework alignment

3. **Document Findings**
   - Export gap analysis reports
   - Prioritize gaps based on risk assessment findings
   - Create remediation roadmap

### **Phase 4: Detection Development**

1. **Prioritize Use Cases**
   - Start with Critical priority items marked as "Not Covered"
   - Focus on high-risk areas identified in your risk assessment
   - Consider compliance deadlines and audit schedules

2. **Develop Detections**
   - For each baseline requirement, create 1-3 specific detection use cases
   - Build and test detection logic in your SIEM
   - Document detection rules and expected alerts

3. **Update Coverage Status**
   - Change `covered` field from "No" to "Partial" or "Yes"
   - Track progress on the dashboard
   - Document any limitations or partial coverage details

### **Phase 5: Continuous Improvement**

1. **Regular Reviews**
   - Quarterly review of the baseline
   - Update coverage status as new detections are deployed
   - Add new requirements based on emerging threats or changes in environment

2. **Metrics and Reporting**
   - Track coverage improvement trends over time
   - Report metrics to leadership and stakeholders
   - Use dashboard for compliance audit evidence

3. **Feedback Loop**
   - Update baseline based on incident learnings
   - Adjust priorities based on threat intelligence
   - Incorporate feedback from SOC analysts on alert quality

---

## Using the Dashboard

### **For Security Teams:**
- **Daily**: Monitor critical gaps and prioritize detection development work
- **Weekly**: Track progress on coverage improvements
- **Monthly**: Report coverage metrics to management
- **Quarterly**: Review and update baseline requirements

### **For Leadership:**
- Use overall coverage percentage as a security KPI
- Understand investment needs based on gap analysis
- Demonstrate due diligence to board and auditors
- Compare coverage across different categories or business units

### **For Auditors:**
- Evidence of systematic approach to security monitoring
- Documentation of coverage gaps and remediation plans
- Compliance framework mapping and coverage
- Continuous monitoring and improvement process

---

## Dashboard Filters and Features

### **Filter Controls:**
- **Category Filter**: Focus on specific technology areas (Endpoint, IAM, Network, etc.)
- **Priority Filter**: View only Critical, High, Medium, or Low priority items
- **Coverage Filter**: Show only Covered, Not Covered, or Partially Covered items

### **Key Metrics:**
- **Overall Coverage %**: Your total monitoring coverage across all requirements
- **Critical Gaps**: Number of critical priority items not yet covered
- **High Priority Gaps**: Number of high priority items not yet covered

### **Visualizations:**
- **Coverage by Category**: See which technology areas are well-covered vs gaps
- **Coverage by Priority**: Understand if you're covering critical items first
- **MITRE Tactics Coverage**: Ensure coverage across the attack lifecycle
- **Compliance Framework Coverage**: Track alignment with regulatory requirements

---

## Best Practices

### **Do's:**
✅ Customize the baseline based on your risk assessment  
✅ Update coverage status regularly as detections are deployed  
✅ Use the dashboard in customer workshops to drive conversations  
✅ Start with critical priorities and work systematically  
✅ Document why certain requirements are not applicable  
✅ Review and update the baseline quarterly  
✅ Use metrics to justify security investments  

### **Don'ts:**
❌ Don't use the example baseline as-is without customization  
❌ Don't skip the risk assessment process  
❌ Don't mark items as "Covered" without testing detections  
❌ Don't ignore compliance-specific requirements  
❌ Don't let the baseline become static - keep it updated  
❌ Don't overwhelm customers with too many requirements at once  

---

## Example Customer Workshop Flow

### **Workshop Agenda (2-3 hours):**

1. **Introduction (15 min)**
   - Explain the purpose of the baseline framework
   - Review the risk assessment process completed

2. **Baseline Review (45 min)**
   - Walk through the example 50 requirements
   - Discuss relevance to customer's environment
   - Add customer-specific requirements
   - Remove non-applicable items

3. **Current State Assessment (45 min)**
   - Review existing monitoring capabilities
   - Populate initial coverage status
   - Identify quick wins (easy-to-implement items)

4. **Dashboard Walkthrough (30 min)**
   - Show live dashboard with customer's data
   - Discuss coverage gaps and priorities
   - Review compliance alignment

5. **Roadmap Planning (30 min)**
   - Prioritize top 10 gaps to address
   - Create phased implementation plan
   - Set target coverage goals (e.g., 80% Critical coverage in 6 months)

---

## Integration with Detection Use Cases

The baseline monitoring requirements serve as the foundation for specific detection use cases. 

**Example Flow:**

**Baseline Requirement:**  
`BL-END-005: Monitor scheduled task and cron job creation`

**Specific Detection Use Cases:**
1. `END_ALT-004`: Suspicious Scheduled Task Creation (already implemented)
2. `END_ALT-005`: Scheduled Task Creation by Non-Admin Users
3. `END_ALT-006`: Scheduled Task Persistence via Startup

Once you've implemented detection use cases that address a baseline requirement, update the `covered` field to track your progress.

---

## Maintenance and Updates

### **Quarterly Review Checklist:**
- [ ] Review threat landscape changes
- [ ] Update priorities based on recent incidents
- [ ] Add new monitoring requirements for new technologies
- [ ] Remove deprecated or decommissioned system requirements
- [ ] Verify compliance framework mappings are current
- [ ] Update coverage status for recently deployed detections
- [ ] Review dashboard metrics trends
- [ ] Update documentation and runbooks

---

## Success Metrics

Track these metrics over time to demonstrate improvement:

1. **Overall Coverage Percentage**: Target 80%+ for Critical/High priority items
2. **Time to Close Gaps**: Average time from "Not Covered" to "Covered"
3. **Critical Gap Count**: Should trend downward over time
4. **Detection Use Cases Deployed**: Number of detections implemented
5. **Compliance Coverage**: Percentage covered for each framework

---

## Support and Customization

This baseline framework is designed to be flexible and adaptable to your organization's needs. As you conduct risk assessments and develop your security monitoring program, continuously refine this baseline to reflect your specific requirements.

Remember: **The goal is not to achieve 100% coverage of a generic baseline, but to achieve comprehensive coverage of YOUR organization's specific risks and monitoring needs.**

---

## Questions to Guide Customization

When working with customers, ask:

1. What are your most critical assets and data?
2. What threats are most relevant to your industry?
3. What compliance frameworks must you adhere to?
4. What monitoring capabilities do you already have?
5. What is your current security maturity level?
6. What is your risk appetite and tolerance?
7. What are your resource constraints (budget, staff, tools)?
8. What are your top 3 security concerns?

Use their answers to customize the baseline requirements and priorities accordingly.

---

**Version:** 1.0  
**Last Updated:** November 2025  
**Status:** Example Framework - Requires Customization Post-Risk Assessment
