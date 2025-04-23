Value | Severity Level | Meaning
0 | Low | Informational, non-critical (e.g., allowed traffic, status messages)
1 | Medium-Low | Minor warnings, policy notifications
2 | Medium | Policy enforcement, denied traffic, system warnings
3 | High | Security alerts, anomalous behavior, matched signatures
4 | Critical | Confirmed threats, malware, intrusion prevention system (IPS) blocks
5 | Very Critical | Severe attacks, lateral movement, or policy breaches involving data exfiltration

```sql
dataSource.name='Check Point Next Generation Firewall' serverHost != 'scalyr-metalog' rule_name='Implied Rule ' service_id='echo-request' icmp_type=8 evidences\[0\].dst_endpoint.ip in('8.8.8.8', '8.8.4.4' )
```

