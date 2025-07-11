| Use Case                                                   | Pattern                                                                                             | Description                                                                                                                                                       |
| ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Unauthorized installation or execution of disallowed apps  | Detect execution events where application name is listed in a disallowed apps list                  | Alert when a user runs or installs an application that is not permitted. MITRE Technique: T1204: User Execution                                                   |
| Sudden spike in usage of high-risk applications            | Count executions of high-risk applications per time window and flag when it exceeds a threshold     | Alert when there is an unexpected surge in use of high-risk applications, indicating possible malicious activity. MITRE Technique: T1204: User Execution          |
| Application version downgrade or tampering                 | Monitor application version or binary hash changes and flag if version decreases or hash mismatches | Alert when an application’s version is rolled back or its binary integrity is altered. MITRE Technique: T1562.003: Impair Defenses: Disable or Modify Tools       |
| Access attempts to newly classified malicious URLs         | Identify HTTP/HTTPS requests to URLs that have been classified as malicious within the last X days  | Alert on attempts to reach URLs newly added to a known-malicious category. MITRE Technique: T1071.001: Application Layer Protocol: Web Protocols                  |
| High volume of URL blocks in short time window             | Count URL block events per user/device within a sliding window and flag high volumes                | Alert when a user or device triggers an unusually large number of URL blocks, suggesting automated or malicious browsing. MITRE Technique: T1595: Active Scanning |
| Repeated user overrides of URL filtering policy            | Track policy-override events and flag when a user exceeds allowed override count                    | Alert when a user repeatedly bypasses URL filtering policies, indicating potential malicious intent or negligence. MITRE Technique: T1562: Impair Defenses        |
| Multiple failed VPN connection attempts                    | Detect successive authentication failures for the same account or source IP within a short period   | Alert on repeated VPN login failures, indicating brute-force or credential-testing attempts. MITRE Technique: T1110: Brute Force                                  |
| VPN login from unusual geolocation                         | Compare successful VPN logins against user’s typical geographic locations and flag anomalies        | Alert when a VPN session originates from a location outside the user’s normal geofence. MITRE Technique: T1078.003: Valid Accounts: External Remote Services      |
| Split-tunnel bypass detected                               | Identify traffic flows marked for split-tunnel that reach disallowed destinations                   | Alert when traffic bypasses VPN tunnel policies, potentially for C2 or data exfiltration. MITRE Technique: T1048: Exfiltration Over Alternative Protocol          |
| Access to known phishing or malware distribution sites     | Match HTTP/HTTPS request URLs against an up-to-date phishing/malware blocklist                      | Alert on user attempts to visit URLs known for phishing or malware hosting. MITRE Technique: T1566.002: Spearphishing Link                                        |
| Unusual browsing patterns outside business hours           | Monitor HTTP activity timestamps and flag browsing events outside defined business hours            | Alert on web activity during off-hours that deviates from normal user behavior. MITRE Technique: T1595: Active Scanning                                           |
| Bypass of URL filtering via encrypted or anonymizing proxy | Detect HTTP requests containing known proxy/anonymizer user-agents or destination domains           | Alert when users attempt to circumvent URL filtering using proxies or anonymizers. MITRE Technique: T1572: Protocol Tunneling                                     |
| Traffic to high-risk or blacklisted IPs                    | Match outbound destination IPs against threat-intelligence blocklists                               | Alert on connections to IP addresses known for C2, malware, or other malicious activity. MITRE Technique: T1071.001: Application Layer Protocol: Web Protocols    |
| Firewall policy violation (blocked port/protocol use)      | Identify sessions blocked by firewall where port or protocol is outside approved list               | Alert on attempts to use disallowed ports or protocols, indicating scanning or policy violations. MITRE Technique: T1046: Network Service Scanning                |
| Excessive connection rate triggering DoS suspicion         | Count connection attempts per source IP in a time window and flag rates above normal levels         | Alert when the number of connections suggests a potential denial-of-service attack. MITRE Technique: T1499: Endpoint Denial of Service                            |


## Unauthorized execution of disallowed apps

Detect execution events where application name is listed in a disallowed apps list.

### Basic Filter

```sql
dataSource.name='Check Point Next Generation Firewall' 
event.type = 'Application Control ' 
cp_app_risk = 'High'
app_properties = * conn_direction='Outgoing '
| filter cs6 contains:anycase ('<UnapprovedApp1>','<UnapprovedApp2>','<UnapprovedApp3>') 
```

---

## Sudden spike in usage of high-risk applications

Count executions of high-risk applications per time window and flag when it exceeds a threshold.

### Basic Filter

```sql
dataSource.name='Check Point Next Generation Firewall' 
event.type = 'Application Control ' 
cp_app_risk contains:anycase ( 'medium', 'high' ) 
```

### PowerQuery
```sql
dataSource.name='Check Point Next Generation Firewall'
event.type = 'Application Control '
cp_app_risk contains:anycase ( 'medium', 'high' ) 
| group 
  src_ip = array_agg_distinct(src), 
  dst_ip = array_agg_distinct(dst), 
  connections = count() 
  by AppName = cs6, timestamp = timebucket('10m'),  conn_direction  
```

## Application version downgrade or tampering events

When an attacker or misconfigured process modifies an application’s installed version or binary unexpectedly, it can indicate malicious activity—such as disabling security controls, introducing back‐doors, or rolling back to a vulnerable release. Detecting these events helps identify attempts to weaken endpoint defenses or persist on a host.

```sql
dataSource.name='Check Point Next Generation Firewall' 
event.type = 'Application Control '
flexString1Label = 'Application Signature ID ' 
| parse ".*flexString1=$flexString1{regex=[0-9:]+}$\\s+.*" from message_extension
| group
  src_ip = array_agg_distinct(src), 
  dst_ip = array_agg_distinct(dst), 
  NoDistinctSignatures = estimate_distinct(flexString1), 
  DistinctSignatures = array_agg_distinct(flexString1),
  EventCount = count()
  by AppName = cs6, timestamp = timebucket()
| filter NoDistinctSignatures > 1
```

## DNS Requests
```sql
dataSource.name='Check Point Next Generation Firewall' 
rule_name='Implied Rule ' service_id='echo-request' 
icmp_type=8 evidences\[0\].dst_endpoint.ip in( '8.8.8.8', '8.8.4.4' )
```
