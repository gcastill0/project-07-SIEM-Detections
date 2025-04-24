### Network Device Password Spraying
Identify brute-force logins on network (VPN, SSH, Web). It maps to MITRE ATT&CK: T1110.003 – Brute Force: Password Spraying.

```sql
dataSource.vendor='Fortinet' 
dataSource.name='FortiGate' 
serverHost != 'scalyr-metalog' 
unmapped.action contains:anycase ('fail', 'denied', 'deny', 'reject') 
unmapped.level contains:anycase ('alert', 'warning') event.type='vpn'
```
> PowerQuery

```sql
dataSource.vendor='Fortinet' 
dataSource.name='FortiGate' 
serverHost != 'scalyr-metalog' 
unmapped.action contains:anycase ('fail', 'denied', 'deny', 'reject') 
unmapped.level contains:anycase ('alert', 'warning') event.type='vpn'
| group count = count() by timestamp = timebucket(), unmapped.remip, srccountry, unmapped.user, unmapped.reason
```

---

### Anomalous Traffic Signaling

Identify regular small packets often used in beaconing (e.g., C2 channels). Port 161 (UDP) – SNMP (Simple Network Management Protocol) is used for device management, polling routers/switches/printers/etc.

This is uncommon in the WAN or DMZ zones, unless the firewall or internal systems are actively polling external SNMP agents, which is a red flag.

High risk if sent outbound — could be a misconfiguration, data leakage, or exfiltration channel. This aligns with MITRE ATT&CK: T1046 – Network Service Scanning, also T1041 – Exfiltration Over C2 Channel if data is being leaked.

```sql
dataSource.vendor='Fortinet' 
dataSource.name='FortiGate' 
serverHost != 'scalyr-metalog' 
event.type='traffic' 
unmapped.dstintfrole contains:anycase ('wan', 'dmz') 
traffic.bytes_out = * dst_endpoint.port contains ('161') 
```

> PowerQuery

```sql
dataSource.vendor='Fortinet' 
dataSource.name='FortiGate' 
serverHost != 'scalyr-metalog' 
event.type='traffic' 
unmapped.dstintfrole contains:anycase ('wan', 'dmz') 
traffic.bytes_out = *
| let bytes_out = number(traffic.bytes_out), event_duration = number(duration)
| filter bytes_out < 100
| filter event_duration > 60
| filter dst_endpoint.port contains ('161') 
| group count = count() by src_endpoint.ip, dst_endpoint.ip, dst_endpoint.port
| sort - dst_endpoint.port
```

---
### Port Scanning Detection
Detect excessive port access attempts from one source. Align with MITRE ATT&CK: T1046 – Network Service Scanning.


```sql
dataSource.vendor='Fortinet' 
dataSource.name='FortiGate' 
serverHost != 'scalyr-metalog' 
event.type='traffic' 
unmapped.dstintfrole contains:anycase ('wan', 'dmz') 
traffic.bytes_in = *
| let bytes_out = number(traffic.bytes_in), event_duration = number(duration)
| filter NOT (src_endpoint.ip matches ("10.0", "10.254", "192.", "172.")) 
| filter NOT (dst_endpoint.port contains ('53'))
| filter isempty(actor.authorizations\[0\].policy.name)
| group count = count() by src_endpoint.ip, dst_endpoint.ip, dst_endpoint.port, timestamp = timebucket('10m')
| sort - count
```

### Lateral Movement (Internal to Internal)
Detect communication between internal IPs over unusual ports or volume. Aligns with MITRE ATT&CK: T1021 – Remote Services.

```sql
dataSource.vendor='Fortinet' dataSource.name='FortiGate' serverHost != 'scalyr-metalog' event.type = * 
| filter dst_endpoint.location.country = 'Reserved' src_endpoint.location.country = 'Reserved'
| filter NOT (dst_endpoint.port contains ('53', '443', '80')) NOT (src_endpoint.port contains ('53', '443', '80'))
| group count = count() by dst_endpoint.location.country, src_endpoint.location.country, dst_endpoint.port, src_endpoint.port, timestamp = timebucket('1m')
```
