# SOC Manager Dashboard - Executive Overview

## Purpose

The SOC Manager Dashboard provides real-time visibility into Security Operations Center (SOC) performance, incident management effectiveness, and team productivity. Designed for managers, team leads, and executives, this dashboard delivers actionable insights without overwhelming detail.

---

## Dashboard Overview

### What It Does

- **Monitors SOC Performance**: Track key metrics in real-time
- **Identifies Bottlenecks**: Spot issues before they become problems
- **Measures Team Efficiency**: Understand analyst productivity and workload
- **Ensures SLA Compliance**: Monitor response and resolution times
- **Tracks Threat Landscape**: Visualize attack patterns via MITRE ATT&CK framework
- **Supports Data-Driven Decisions**: Use metrics to optimize operations

### Who Uses It

- **SOC Managers**: Daily operational oversight
- **Security Leadership**: Weekly and monthly reviews
- **Executive Team**: Quarterly security briefings
- **HR/Operations**: Workload planning and resource allocation

---

## Key Performance Indicators (KPIs)

### 1. Total Incidents
**What it shows:** Number of security incidents created in the selected time period

**Why it matters:**
- Indicates overall security event volume
- Helps with capacity planning
- Shows if detection coverage is increasing

**Healthy Range:** 
- Small SOC: 20-50 incidents/week
- Medium SOC: 50-150 incidents/week
- Large SOC: 150+ incidents/week

**Color Coding:**
- 🟢 Green: Normal operations
- 🟡 Yellow: Elevated activity
- 🟠 Orange: High volume
- 🔴 Red: Potentially overwhelming

---

### 2. Open Incidents
**What it shows:** Current count of incidents awaiting attention

**Why it matters:**
- Direct indicator of backlog
- Shows if team is keeping up with workload
- Immediate action metric

**Target:** <5 open incidents at any time

**When to act:**
- 🟡 Yellow (5-10): Review assignment process
- 🔴 Red (10+): Immediate intervention needed - redistribute work, bring in additional resources

---

### 3. Critical/High Priority Incidents
**What it shows:** Active incidents with critical or high severity

**Why it matters:**
- These represent the greatest risk to the organization
- Require immediate attention and senior analyst expertise
- May indicate active compromise or significant vulnerability

**Target:** <3 active high-severity incidents

**When to act:**
- Any critical incident: Immediate escalation
- 3+ high severity: All-hands response, consider incident response team activation

---

### 4. Mean Time to Assign (MTTA)
**What it shows:** Average time from incident creation to analyst assignment

**Why it matters:**
- Measures initial response capability
- Indicates SOC alertness and coverage
- Shows if incidents sit unnoticed

**Industry Standards:**
- 🟢 Excellent: <30 minutes
- 🟡 Good: 30-60 minutes
- 🟠 Needs Improvement: 1-2 hours
- 🔴 Poor: >2 hours

**How to improve:**
- Implement auto-assignment rules
- Ensure 24/7 coverage
- Set up escalation procedures

---

### 5. Mean Time to Close (MTTC)
**What it shows:** Average time from incident creation to resolution

**Why it matters:**
- Overall measure of investigation efficiency
- Indicates if team has proper tools and training
- Shows process effectiveness

**Targets by Severity:**
- Critical: <4 hours
- High: <24 hours
- Medium: <48 hours
- Low: <72 hours

**Factors affecting MTTC:**
- Complexity of incidents
- Availability of tools and logs
- Analyst skill and experience
- Quality of playbooks/documentation

---

## Trend Analysis

### Incident Volume Trends
**Daily incident creation stacked by severity**

**What to look for:**
- **Sudden spikes**: May indicate active campaign or new vulnerability
- **Gradual increase**: Growing attack surface or improved detection
- **Decreasing trends**: Successful tuning or reduced threats
- **Severity shifts**: More high-severity incidents may indicate targeted attacks

**Use cases:**
- Identify peak days/times for staffing
- Spot anomalies requiring investigation
- Demonstrate security posture improvements to leadership

---

### Resolution Rate
**Percentage of incidents closed each day**

**What to look for:**
- **Target**: >80% daily resolution rate
- **Declining rate**: Team capacity issues or complex incident surge
- **Consistent low rate**: Process or training gaps

**Use cases:**
- Early warning of team burnout
- Validate process improvements
- Support resource requests

---

## Distribution and Coverage

### Current Incident Status
**Breakdown of open, investigating, and closed incidents**

**Healthy Distribution:**
- Open: <20% (awaiting triage)
- Investigating: 30-40% (active work)
- Closed: 40-50% (resolved)

**Unhealthy Patterns:**
- >40% Open: Assignment/triage bottleneck
- >50% Investigating: Resolution bottleneck or complex cases
- <20% Closed: Team not closing incidents properly

---

### Incidents by Severity
**Distribution across critical, high, medium, low**

**What to look for:**
- **Majority low/medium**: Normal operations, effective prevention
- **High percentage critical/high**: Active threats or poor detection tuning
- **All low severity**: May indicate detection gaps for serious threats

**Use cases:**
- Validate alert tuning effectiveness
- Prioritize detection development
- Justify security investments

---

### MITRE ATT&CK Coverage
**Top 10 attack tactics detected**

**What it shows:**
- Which parts of the attack lifecycle you're detecting
- Common attacker behaviors in your environment
- Coverage gaps in detection strategy

**Common Tactics:**
- **Execution**: Attackers running code
- **Persistence**: Maintaining access
- **Privilege Escalation**: Gaining higher access
- **Defense Evasion**: Avoiding detection
- **Credential Access**: Stealing passwords

**Use cases:**
- Identify attack patterns
- Prioritize security control investments
- Plan detection development roadmap
- Brief leadership on threat landscape

---

## Team Performance

### Analyst Workload Distribution
**Shows each analyst's incident load and productivity**

**Key Metrics Per Analyst:**
- **Total Assigned**: All incidents assigned
- **Open**: Incidents not yet started
- **Investigating**: Active investigations
- **Closed**: Resolved incidents
- **High Priority**: Critical/High severity count
- **Workload Score**: Calculated burden metric

**Workload Score Calculation:**
```
Score = (Open × 3) + (Investigating × 2) + (High Priority × 2)
```

**Why weighted?**
- Open incidents require most effort (planning, triage)
- Investigating takes sustained focus
- High priority adds stress and urgency

**Healthy Workload Score:** <30 per analyst

**Use cases:**
- Identify overloaded team members
- Balance assignment distribution
- Recognize high performers
- Plan hiring needs
- Support performance reviews

---

## Operational Focus

### Top Alert Types
**Which detection rules generate the most incidents**

**What to look for:**
- **One alert dominating**: Likely needs tuning
- **False positive indicators**: High volume, mostly closed quickly
- **High-value alerts**: Lower volume but high severity

**Use cases:**
- Prioritize alert tuning efforts
- Identify successful detection rules
- Justify resources for detection engineering
- Reduce analyst fatigue from noisy alerts

---

### Critical Incidents Requiring Attention
**Active high-severity incidents with age tracking**

**What it shows:**
- Incidents that need immediate attention
- How long each has been open
- Who's assigned and current status

**Color Coding:**
- Age: Green (<12h), Yellow (12-24h), Red (>24h)
- Severity: Red (Critical), Orange (High)

**Daily action item:**
- Review this table every morning
- Follow up on aging incidents
- Ensure proper resources allocated

---

## SLA Compliance

### Assignment SLA
**Target: <1 hour from creation to assignment**

**Why this matters:**
- First response is critical
- Shows 24/7 monitoring effectiveness
- Demonstrates SOC responsiveness

**Typical Results:**
- 🟢 90%+ compliance: Excellent
- 🟡 70-89% compliance: Good, room for improvement
- 🔴 <70% compliance: Coverage gaps, process issues

---

### Resolution SLA
**Targets vary by severity:**

| Severity | Target | Rationale |
|----------|--------|-----------|
| Critical | 4 hours | Active threat, immediate response |
| High | 24 hours | Likely compromise, urgent investigation |
| Medium | 48 hours | Suspicious activity, timely review |
| Low | 72 hours | Informational, document and close |

**What affects compliance:**
- Incident complexity
- Available evidence/logs
- Analyst experience
- Tool availability
- External dependencies (vendor support, legal review)

**Realistic expectations:**
- 80%+ compliance: Excellent
- 70-79% compliance: Good
- <70% compliance: Review processes and resources

---

## How to Use This Dashboard

### Daily Review (5 minutes)
**Morning Standup Check:**
1. Open Incidents - any spike overnight?
2. Critical/High Priority - what needs immediate attention?
3. Critical Incidents table - follow up on aging items
4. Team workload - anyone overloaded?

**Actions:**
- Assign urgent incidents
- Redistribute workload if needed
- Escalate aging critical incidents

---

### Weekly Review (15 minutes)
**Team Meeting Agenda:**
1. Incident volume trend - any patterns?
2. Resolution rate - maintaining targets?
3. Top alert types - any needing tuning?
4. Workload distribution - balanced?
5. SLA compliance - meeting goals?

**Actions:**
- Plan alert tuning projects
- Adjust assignment strategy
- Recognize team achievements
- Address bottlenecks

---

### Monthly Review (30 minutes)
**Leadership Briefing:**
1. Change time range to 30 days
2. Review all metrics for trends
3. MITRE ATT&CK coverage analysis
4. Team performance and capacity
5. SLA compliance trends

**Actions:**
- Report to executive leadership
- Request resources based on data
- Plan process improvements
- Set goals for next month

---

### Quarterly Review (1 hour)
**Strategic Planning:**
1. 90-day trend analysis
2. Team growth and development
3. Detection coverage assessment
4. Process maturity evaluation
5. Budget and resource planning

**Deliverables:**
- Executive security briefing
- Resource allocation plan
- Detection development roadmap
- Training and development plan

---

## Interpreting the Metrics

### Scenario 1: Healthy SOC
```
✅ Total Incidents: 45
✅ Open: 3
✅ Critical/High: 1
✅ MTTA: 0.8 hours
✅ MTTC: 18 hours
✅ Resolution Rate: 85%
✅ SLA Compliance: 90%
```

**Interpretation:** SOC is operating efficiently within targets. Continue monitoring and maintain current processes.

---

### Scenario 2: Overloaded Team
```
🔴 Total Incidents: 120
🔴 Open: 25
🔴 Critical/High: 8
🔴 MTTA: 4.5 hours
🔴 MTTC: 72 hours
🔴 Resolution Rate: 45%
🔴 SLA Compliance: 40%
```

**Interpretation:** Team is overwhelmed and cannot keep pace.

**Immediate Actions:**
- Redistribute existing workload
- Bring in temporary support (contractors, on-call staff)
- Review alert tuning urgently
- Escalate to leadership for resources

**Long-term Actions:**
- Hire additional analysts
- Implement automation
- Improve alert quality
- Enhance playbooks/tools

---

### Scenario 3: Alert Tuning Needed
```
🟠 Total Incidents: 200 (high)
✅ Resolution Rate: 95% (excellent)
✅ MTTC: 2 hours (very fast)
🟠 Top Alert: END_ALT-002 (80 incidents)
```

**Interpretation:** One alert generating many quick-close incidents (likely false positives)

**Actions:**
- Review END_ALT-002 detection logic
- Analyze closed incidents for patterns
- Add exceptions or adjust thresholds
- May reduce incident volume by 40%

**Expected Improvement:**
- Lower total incidents
- Better analyst morale
- More time for complex investigations

---

### Scenario 4: Workload Imbalance
```
Analyst A: 45 incidents, Workload Score: 67
Analyst B: 12 incidents, Workload Score: 18
Analyst C: 15 incidents, Workload Score: 22
```

**Interpretation:** Analyst A is carrying disproportionate load

**Possible Causes:**
- Most experienced analyst getting hardest cases
- Auto-assignment rules favoring one person
- Other analysts not picking up new incidents

**Actions:**
- Redistribute Analyst A's open incidents
- Review assignment criteria
- Cross-train team for complex cases
- Consider if Analyst A needs promotion/recognition

---

## Best Practices

### Setting Realistic Targets

**Start Conservative, Improve Gradually**

Don't aim for perfection immediately:
- Year 1: Establish baselines, aim for 70% SLA compliance
- Year 2: Process improvements, target 80% compliance
- Year 3: Mature operations, achieve 90%+ compliance

**Document Everything**
- Baseline metrics when starting
- Changes made and their impact
- Quarterly improvement reports

---

### Communication

**With Your Team:**
- Share metrics transparently
- Celebrate improvements
- Use data to support, not punish
- Ask for feedback on targets

**With Leadership:**
- Present trends, not just numbers
- Connect metrics to business risk
- Request resources with data justification
- Highlight team achievements

**With Other Teams:**
- Share threat intelligence insights
- Demonstrate SOC value
- Collaborate on risk reduction

---

### Continuous Improvement

**Monthly Actions:**
1. Identify one bottleneck
2. Implement one improvement
3. Measure impact
4. Adjust and repeat

**Common Improvements:**
- Alert tuning (reduce noise)
- Playbook development (speed resolution)
- Automation (reduce manual work)
- Training (improve skills)
- Tool optimization (better efficiency)

---

### Avoiding Common Pitfalls

**Don't:**
- ❌ Use metrics to punish analysts
- ❌ Set unrealistic targets
- ❌ Ignore context (incident complexity varies)
- ❌ Compare analysts without considering case mix
- ❌ Focus solely on speed over quality

**Do:**
- ✅ Use metrics to identify systemic issues
- ✅ Adjust targets based on reality
- ✅ Consider qualitative factors
- ✅ Recognize different strengths
- ✅ Balance efficiency with thoroughness

---

## Key Takeaways

### Purpose of Metrics
Metrics are tools to:
- **Improve operations**, not punish people
- **Identify trends**, not create blame
- **Support decisions**, not replace judgment
- **Measure progress**, not create pressure

### What Makes a Good SOC
- **Responsive**: Fast initial response (MTTA)
- **Efficient**: Timely resolution (MTTC)
- **Balanced**: Even workload distribution
- **Quality-Focused**: High resolution rates with low false positives
- **Adaptive**: Continuously improving based on data

### Success Indicators
- ✅ Consistent SLA compliance (80%+)
- ✅ Balanced team workload
- ✅ Declining incident volume (better prevention)
- ✅ Improving resolution times
- ✅ High team morale and low turnover

---

## Getting Started

### Week 1: Establish Baseline
- Install dashboard
- Document current metrics
- Share with team
- Set initial realistic targets

### Week 2-4: Observe and Learn
- Watch trends
- Identify patterns
- Don't make drastic changes
- Build team trust in metrics

### Month 2: First Improvements
- Pick one issue to address
- Implement change
- Measure impact
- Communicate results

### Month 3+: Continuous Optimization
- Regular review cadence
- Incremental improvements
- Team feedback integration
- Progress celebration

---

## Support and Resources

### Dashboard Customization
The dashboard can be customized for your environment:
- Adjust SLA thresholds
- Modify color ranges
- Add organization-specific metrics
- Change time range defaults

### Training
Ensure all stakeholders understand:
- What each metric means
- How to interpret trends
- When to take action
- How to access the dashboard

### Documentation
Keep updated:
- SOC processes and procedures
- SLA definitions and targets
- Escalation procedures
- Incident response playbooks

---

## Conclusion

The SOC Manager Dashboard transforms incident data into actionable intelligence. Use it to:

**Operationally:**
- Monitor daily SOC health
- Respond quickly to issues
- Optimize team performance

**Tactically:**
- Plan resource allocation
- Prioritize improvements
- Tune detection rules

**Strategically:**
- Demonstrate SOC value
- Justify investments
- Guide security strategy

**Remember:** The goal is continuous improvement, not perfection. Use these metrics as a compass to guide your SOC toward operational excellence.

---

**Document Version:** 1.0  
**Last Updated:** November 2025  
**Maintained By:** SOC Leadership Team
