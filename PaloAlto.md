```sql
dataSource.name='Palo Alto Networks Firewall' connection_info.protocol_name in ( 'tcp' ) NOT (dst_endpoint.ip matches ("10.", "192.", "172."))
| let dst_endpoint.country = geo_ip_country(dst_endpoint.ip)
| group count = count() by dst_endpoint.country, src_endpoint.ip, dst_endpoint.ip, dst_endpoint.port, unmapped.policy_id, event.type
| filter dst_endpoint.country contains:anycase ("Russia", "Iran", "North Korea", "China", "Syria")
```

```sql
dataSource.name='Palo Alto Networks Firewall' connection_info.protocol_name in ( 'tcp' ) NOT (dst_endpoint.ip matches ("10.", "192.", "172.")) 
| let dst_endpoint.country = geo_ip_country(dst_endpoint.ip)
| group count = count() by dst_endpoint.country, src_endpoint.ip, dst_endpoint.ip, dst_endpoint.port, unmapped.policy_id, event.type
| filter dst_endpoint.country contains:anycase ("Russia", "Iran", "North Korea", "China", "Syria")
| group count2 = count() by dst_endpoint.ip
```

```sql
dataSource.name='Palo Alto Networks Firewall' connection_info.protocol_name in ( 'tcp' ) NOT (dst_endpoint.ip matches ("10.", "192.", "172.")) 
| let dst_endpoint.country = geo_ip_country(dst_endpoint.ip)
| group count = count() by dst_endpoint.country, src_endpoint.ip, dst_endpoint.ip, dst_endpoint.port, unmapped.policy_id, event.type
| filter dst_endpoint.country contains:anycase ("Russia", "Iran", "North Korea", "China", "Syria")
| group offending_ips = array_agg_distinct(dst_endpoint.ip)
| sort - offending_ips
```

```sql
dataSource.name='Palo Alto Networks Firewall' 
connection_info.protocol_name in ( 'tcp' ) 
unmapped.action = 'Allow'
dst_endpoint.location.region matches ('Russia', 'Iran', 'North Korea', 'China', 'Syria')
```

```sql
dataSource.name='Palo Alto Networks Firewall' 
connection_info.protocol_name in ( 'tcp' ) 
unmapped.action = 'allow'
dst_endpoint.location.region matches ('Russia', 'Iran', 'North Korea', 'China', 'Syria')
| group offending_ips = array_agg_distinct(dst_endpoint.ip)
```