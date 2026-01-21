# Correlate Blocked Client Activity

This search analyzes Microsoft Azure Front Door Web Application Firewall (WAF) logs to identify client activity associated with elevated risk.

- It first isolates requests where the WAF reports “Inbound Anomaly Score Exceeded,” indicating behavior that surpasses Microsoft’s anomaly threshold, while filtering out common default rule noise. 
- Then correlates those anomaly events with the corresponding client IP activity using a shared tracking reference, aggregating targeted hosts, request URIs, triggered rules, and message context. 
- The result is a ranked view of client IPs whose requests most frequently contributed to high-risk WAF detections, providing clear investigative context for potential web-based attacks.

## Net outcome

A ranked list of client IPs and their associated trackingReference where Inbound Anomaly Score Exceeded occurred, with context: targeted hosts, URIs, triggered WAF rules, messages, and count, while filtering out two excluded rule families.

## Build a list of “interesting” tracking references

To build a list of **“interesting” tracking references**, the search first narrows the data to **high-signal WAF events** and then extracts the identifiers that tie related requests together.

It does this by querying **Microsoft Azure Front Door Web Application Firewall logs** and applying the following logic:

- **Scope to the correct data source**: Only events from Microsoft’s Front Door WAF are considered, ensuring the tracking reference reflects a single WAF inspection context.
<br>

- **Reduce noise from default rules**: Two common default rule families—Local File Inclusion and protocol enforcement—are explicitly excluded. These rules often trigger benign or low-value alerts and would otherwise overwhelm the results.
<br>

- **Select a high-risk condition**:  The filter is constrained to events where the WAF message is **“Inbound Anomaly Score Exceeded


```sql
dataSource.vendor = 'Microsoft' 
  unmapped.category = 'FrontDoorWebApplicationFirewallLog' 
  NOT ( unmapped.properties.ruleName contains 'Microsoft_DefaultRuleSet-2.1-LFI-930130') 
  NOT ( unmapped.properties.ruleName contains 'Microsoft_DefaultRuleSet-2.1-PROTOCOL-ENFORCEMENT') 
  unmapped.properties.details.msg='Inbound Anomaly Score Exceeded'
  | group count = count() by unmapped.properties.trackingReference
  | columns unmapped.properties.trackingReference
```

## Build enriched “blocked activity” records

Search groups related WAF events into a concise summary that is easier to investigate.

Consider the same Azure Front Door WAF logs and applies the same rule exclusions to reduce noise. Events are then grouped by client IP and tracking reference, allowing multiple rule triggers from the same request flow to be analyzed together. For each group, the search aggregates the targeted hosts, request URIs, triggered rules, and WAF messages, and counts how often rules were triggered.

The result is a single, enriched record per client and tracking reference that shows who triggered the WAF, what was targeted, and how frequently, providing clear context for security analysis.

```sql
  dataSource.vendor = 'Microsoft' 
  unmapped.category = 'FrontDoorWebApplicationFirewallLog' 
  NOT ( unmapped.properties.ruleName contains 'Microsoft_DefaultRuleSet-2.1-LFI-930130') 
  NOT ( unmapped.properties.ruleName contains 'Microsoft_DefaultRuleSet-2.1-PROTOCOL-ENFORCEMENT')
  | group TargetedHost = array_agg_distinct(unmapped.properties.host),
    TriggeringRules = array_agg_distinct(unmapped.properties.ruleName),
    Messages = array_agg_distinct(unmapped.properties.details.msg),
    DistinctURIsTargeted = array_agg_distinct(unmapped.properties.requestUri),
    BlockedRuleTriggerCount = count() by ClientIP = unmapped.properties.clientIP, unmapped.properties.trackingReference
```

## Join the two sets on `trackingReference`

The join is used to correlate high-risk anomaly detections with the client activity that caused them.

First, one side of the join produces a list of tracking references associated with the WAF message `Inbound Anomaly Score Exceeded`. These tracking references represent request flows that Microsoft’s WAF has already identified as anomalous.

The other side builds detailed activity summaries for all clients, grouped by client IP and tracking reference. This includes the hosts, URIs, rules triggered, and the volume of rule hits.

```sql
| join 
trackingReference = (
  dataSource.vendor = 'Microsoft' 
  unmapped.category = 'FrontDoorWebApplicationFirewallLog' 
  NOT ( unmapped.properties.ruleName contains 'Microsoft_DefaultRuleSet-2.1-LFI-930130') 
  NOT ( unmapped.properties.ruleName contains 'Microsoft_DefaultRuleSet-2.1-PROTOCOL-ENFORCEMENT') 
  unmapped.properties.details.msg='Inbound Anomaly Score Exceeded'
  | group count = count() by unmapped.properties.trackingReference
  | columns unmapped.properties.trackingReference
),
blocked = ( 
  dataSource.vendor = 'Microsoft' 
  unmapped.category = 'FrontDoorWebApplicationFirewallLog' 
  NOT ( unmapped.properties.ruleName contains 'Microsoft_DefaultRuleSet-2.1-LFI-930130') 
  NOT ( unmapped.properties.ruleName contains 'Microsoft_DefaultRuleSet-2.1-PROTOCOL-ENFORCEMENT')
  | group TargetedHost = array_agg_distinct(unmapped.properties.host),
    TriggeringRules = array_agg_distinct(unmapped.properties.ruleName),
    Messages = array_agg_distinct(unmapped.properties.details.msg),
    DistinctURIsTargeted = array_agg_distinct(unmapped.properties.requestUri),
    BlockedRuleTriggerCount = count() by ClientIP = unmapped.properties.clientIP, unmapped.properties.trackingReference
) on unmapped.properties.trackingReference
| sort - BlockedRuleTriggerCount
```