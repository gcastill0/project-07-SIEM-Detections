## **Outbound SMB Traffic Detection**
```sql
dataSource.name = 'Cisco Meraki MX Firewall' 
dst.port.number in (445, 139) 
connection_info.protocol_name = "tcp" 
NOT (dst.ip.address matches ("10.0", "192.", "172."))
```

> PowerQuery

```sql
dataSource.name = 'Cisco Meraki MX Firewall' dst.port.number in (445, 139) connection_info.protocol_name = "tcp" NOT (dst.ip.address matches ("10.0", "192.", "172."))
| group count = count() by src.ip.address, dst.ip.address
| let country = geo_ip_country(dst.ip.address)
| sort - count
```
Detects SMB traffic leaving the network perimeter (often a sign of misconfiguration or worm activity).

---

## **Suspicious Traffic on TOR Port**
```sql
dataSource.name = 'Cisco Meraki MX Firewall' 
dst.port.number in (9001, 9030, 9050, 9051)
connection_info.protocol_name in ("tcp", "udp")
```

> PowerQuery 

```sql
dataSource.name = 'Cisco Meraki MX Firewall' 
dst.port.number in (9001, 9030, 9050, 9051)
connection_info.protocol_name in ("tcp", "udp")
| group count = count() by src.ip.address, dst.ip.address, dst.port.number
| group dest_ips = array_agg_distinct(dst.ip.address) by src.ip.address, string(dst.port.number)
| let len = len(dest_ips) 
| sort - len
```

Flags outbound connections to common TOR entry or relay ports.

---

## **Traffic to Suspicious Countries**

> PowerQuery

```sql
dataSource.name = 'Cisco Meraki MX Firewall' 
| let dst.geo.country = geo_ip_country(dst.ip.address)
| filter dst.geo.country in ("Russia", "Iran", "North Korea", "China", "Syria")
| filter connection_info.protocol_name in ("tcp", "udp")
| group count = count() by device.hostname, src.ip.address, dst.ip.address, dst.geo.country, connection_info.protocol_name, dst.port.number 
```
Detects communications with high-risk geolocations.

> Note: Requires enrichment of `dst.geo.country`. 


---

## **Network Device Password Spraying**
```sql
dataSource.name = 'Cisco Meraki MX Firewall' 
event.type = 'firewall' 
dst.port.number in (22, 23, 443, 161, 80) 
event.network.connectionStatus = 'deny all'
```
Detects attempts to brute-force or spray credentials across network gear (via SSH, Telnet, SNMP, etc.).

---

## **High Volume Traffic from a Single IP**

> PowerQuery

```sql
dataSource.name = 'Cisco Meraki MX Firewall' 
NOT (dst.port.number in (22, 23, 443, 161, 80))
| group count = count() by src.ip.address, dst.ip.address, timestamp = timebucket('10m')
| sort - count
```

Identifies hosts generating excessive network activity, possibly due to scanning, malware, or exfiltration.

---

## **Detect Outbound LDAP Traffic**
```sql
dataSource.name = 'Cisco Meraki MX Firewall'
dst.port.number in (389, 636)
connection_info.protocol_name = "tcp"
NOT (dst.ip.address matches ("10.0", "192.", "172."))
```
---
> PowerQuery

```sql
dataSource.name = 'Cisco Meraki MX Firewall'
dst.port.number in (389, 636)
connection_info.protocol_name = "tcp"
NOT (dst.ip.address matches ("10.0", "192.", "172"))
| let dst.geo.country = geo_ip_country(dst.ip.address)
| group count = count() by src.ip.address, dst.geo.country, dst.ip.address
```

LDAP should rarely leave the network perimeter.

---

## **Anomalous Connection Pattern: Single Source to Multiple Users**
```sql
dataSource.name = 'Cisco Meraki MX Firewall' event.type = 'firewall' 
| group count = count() by src.ip.address, dst.ip.address
| group sum = sum(count), destinations = array_agg_distinct(dst.ip.address) by src.ip.address
| let number_of_targets = len(destinations)
| sort - sum

```
> Common ≠ Safe: Attackers often hide malicious traffic behind common ports (e.g., data exfiltration over 443 or DNS tunneling on 53).

Flags scanning or malware propagation behavior.

