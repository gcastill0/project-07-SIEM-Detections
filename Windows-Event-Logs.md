| Correlation | Events | Use Case |
| :--- | --- | --- |
| Brute Force | 4625 (multiple failed logon attempts), followed by 4624 (successful logon) | Detects possible brute-force or credential-stuffing attacks by correlating multiple failed logons with a subsequent successful logon. |
| Privilege Escalation | 4720 (new account creation), followed by 4672 (special privileges assigned) | Identifies unauthorized privilege escalation by detecting when new accounts are granted elevated privileges. |
| Persistence Mechanism Identification |  7045 (service installed) or 4698 (scheduled task created), after a privileged event (4672) | Tracks persistence attempts by correlating new services or scheduled tasks with privileged access events. |
| Lateral Movement | 4624 (successful logon) across multiple hosts with 5140 (network share access) | Highlights lateral movement by detecting multiple successful logons across hosts followed by network share accesses. |
| Data Exfiltration | 4663 (access to sensitive files) followed by 5156 (outbound network connection) | Detects potential data exfiltration by correlating access to sensitive files with outbound connections.|

---

# Brute Force

### Failed Logon Attempts
```sql
dataSource.name='Windows Event Logs' winEventLog.id=4625
| group count = count() by endpoint.name, timestamp = timebucket()
```

### Successful Logon
```sql
dataSource.name='Windows Event Logs' winEventLog.id=4624
| group count = count() by endpoint.name, timestamp = timebucket()
```

### Correlation matching on `endpoint.name`
```sql
| join 
FAILED_LOGON = (
    dataSource.name='Windows Event Logs' winEventLog.id=4625
    | group count = count() by endpoint.name, timestamp = timebucket('10m')
),
SUCCESSFUL_LOGON = (
    dataSource.name='Windows Event Logs' winEventLog.id=4624
    | group count = count() by endpoint.name, timestamp = timebucket('10m')
) 
on endpoint.name, timestamp 
```

### Correlation matching on `endpoint.name` enriched with Lookup data
```sql
| join 
FAILED_LOGON = (
    dataSource.name='Windows Event Logs' 
    | filter winEventLog.id=4625
    | let winEventLog.id = string(winEventLog.id)
    | group count = count() by endpoint.name, winEventLog.id, timestamp = timebucket('10m')
    | lookup Category,Subcategory, "Message Summary" from WindowsSecurityAuditEvents.csv by Event_ID = winEventLog.id
),
SUCCESSFUL_LOGON = (
    dataSource.name='Windows Event Logs' 
    | filter winEventLog.id=4624
    | let winEventLog.id = string(winEventLog.id)
    | group count = count() by endpoint.name, winEventLog.id, timestamp = timebucket('10m')
    | lookup Category,Subcategory, "Message Summary" from WindowsSecurityAuditEvents.csv by Event_ID = winEventLog.id
) 
on endpoint.name, timestamp 
```

| endpoint.name | FAILED_LOGON.winEventLog.id | timestamp               | FAILED_LOGON.count | FAILED_LOGON.Category | FAILED_LOGON.Subcategory | FAILED_LOGON.Message Summary | SUCCESSFUL_LOGON.winEventLog.id | SUCCESSFUL_LOGON.count | SUCCESSFUL_LOGON.Category | SUCCESSFUL_LOGON.Subcategory | SUCCESSFUL_LOGON.Message Summary       |
| ------------- | --------------------------- | ----------------------- | -----------------: | --------------------- | ------------------------ | ---------------------------- | ------------------------------- | ---------------------: | ------------------------- | ---------------------------- | -------------------------------------- |
| SKYNET        | 4625                        | Nov 1 · 9:00:00.000 am  |                  5 | Logon/Logoff          | Logon                    | An account failed to log on. | 4624                            |                      6 | Logon/Logoff              | Logon                        | An account was successfully logged on. |
| SKYNET        | 4625                        | Nov 5 · 8:40:00.000 am  |                  5 | Logon/Logoff          | Logon                    | An account failed to log on. | 4624                            |                      6 | Logon/Logoff              | Logon                        | An account was successfully logged on. |
| SKYNET        | 4625                        | Nov 6 · 12:50:00.000 am |                  5 | Logon/Logoff          | Logon                    | An account failed to log on. | 4624                            |                      6 | Logon/Logoff              | Logon                        | An account was successfully logged on. |
| SKYNET        | 4625                        | Nov 6 · 9:30:00.000 pm  |                  6 | Logon/Logoff          | Logon                    | An account failed to log on. | 4624                            |                     10 | Logon/Logoff              | Logon                        | An account was successfully logged on. |

# Privilege Escalation

### Correlation matching on `endpoint.name` enriched with Lookup data

```sql
| join 
NEW_ACCOUNT = (
    dataSource.name='Windows Event Logs' 
    | filter winEventLog.id=4720
    | let winEventLog.id = string(winEventLog.id)
    | group count = count() by endpoint.name, winEventLog.id, timestamp = timebucket('10m')
    | lookup Category,Subcategory, "Message Summary" from WindowsSecurityAuditEvents.csv by Event_ID = winEventLog.id
),
PRIVILEGES_ASSIGNED = (
    dataSource.name='Windows Event Logs' 
    | filter winEventLog.id=4672
    | let winEventLog.id = string(winEventLog.id)
    | group count = count() by endpoint.name, winEventLog.id, timestamp = timebucket('10m')
    | lookup Category,Subcategory, "Message Summary" from WindowsSecurityAuditEvents.csv by Event_ID = winEventLog.id
) 
on endpoint.name, timestamp 
```

| endpoint.name | NEW_ACCOUNT.winEventLog.id | timestamp               | NEW_ACCOUNT.count | NEW_ACCOUNT.Category | NEW_ACCOUNT.Subcategory | NEW_ACCOUNT.Message Summary | PRIVILEGES_ASSIGNED.winEventLog.id | PRIVILEGES_ASSIGNED.count | PRIVILEGES_ASSIGNED.Category | PRIVILEGES_ASSIGNED.Subcategory                       | PRIVILEGES_ASSIGNED.Message Summary       |
| ------------- | -------------------------- | ----------------------- | ----------------: | -------------------- | ----------------------- | --------------------------- | ---------------------------------- | ------------------------: | ---------------------------- | ----------------------------------------------------- | ----------------------------------------- |
| THEBORG       | 4720                       | Nov 1 · 9:20:00.000 am  |                 1 | Account Management   | User Account Management | A user account was created. | 4672                               |                        77 | Privilege Use                | Sensitive Privilege Use / Non Sensitive Privilege Use | Special privileges assigned to new logon. |
| THEBORG       | 4720                       | Nov 5 · 9:00:00.000 am  |                 1 | Account Management   | User Account Management | A user account was created. | 4672                               |                        34 | Privilege Use                | Sensitive Privilege Use / Non Sensitive Privilege Use | Special privileges assigned to new logon. |
| THEBORG       | 4720                       | Nov 6 · 1:10:00.000 am  |                 1 | Account Management   | User Account Management | A user account was created. | 4672                               |                        36 | Privilege Use                | Sensitive Privilege Use / Non Sensitive Privilege Use | Special privileges assigned to new logon. |
| THEBORG       | 4720                       | Nov 6 · 10:00:00.000 pm |                 1 | Account Management   | User Account Management | A user account was created. | 4672                               |                        68 | Privilege Use                | Sensitive Privilege Use / Non Sensitive Privilege Use | Special privileges assigned to new logon. |

# Persistence Mechanism Identification

### Correlation matching on `endpoint.name` enriched with Lookup data
```sql
| join 
PRIVILEGES_ASSIGNED = (
    dataSource.name='Windows Event Logs' 
    | filter winEventLog.id=4672
    | let winEventLog.id = string(winEventLog.id)
    | group count = count() by endpoint.name, winEventLog.id, timestamp = timebucket('10m')
    | lookup Category,Subcategory, "Message Summary" from WindowsSecurityAuditEvents.csv by Event_ID = winEventLog.id
),
NEW_SERVICES = (
    dataSource.name='Windows Event Logs' 
    | filter ( winEventLog.id=7045 OR winEventLog.id=4698 )
    | let winEventLog.id = string(winEventLog.id)
    | group count = count() by endpoint.name, winEventLog.id, timestamp = timebucket('10m')
    | lookup Category,Subcategory, "Message Summary" from WindowsSecurityAuditEvents.csv by Event_ID = winEventLog.id
) 
on endpoint.name, timestamp 
```

| endpoint.name | PRIVILEGES_ASSIGNED.winEventLog.id | timestamp               | PRIVILEGES_ASSIGNED.count | PRIVILEGES_ASSIGNED.Category | PRIVILEGES_ASSIGNED.Subcategory                       | PRIVILEGES_ASSIGNED.Message Summary       | NEW_SERVICES.winEventLog.id | NEW_SERVICES.count | NEW_SERVICES.Category | NEW_SERVICES.Subcategory   | NEW_SERVICES.Message Summary                                     |
| ------------- | ---------------------------------- | ----------------------- | ------------------------: | ---------------------------- | ----------------------------------------------------- | ----------------------------------------- | --------------------------- | -----------------: | --------------------- | -------------------------- | ---------------------------------------------------------------- |
| THEBORG       | 4672                               | Nov 1 · 9:30:00.000 am  |                        86 | Privilege Use                | Sensitive Privilege Use / Non Sensitive Privilege Use | Special privileges assigned to new logon. | 7045                        |                  1 | System                |  Security System Extension | A new service was installed by the user indicated in the subject |
| THEBORG       | 4672                               | Nov 5 · 9:10:00.000 am  |                        68 | Privilege Use                | Sensitive Privilege Use / Non Sensitive Privilege Use | Special privileges assigned to new logon. | 7045                        |                  1 | System                |  Security System Extension | A new service was installed by the user indicated in the subject |
| THEBORG       | 4672                               | Nov 6 · 1:20:00.000 am  |                        66 | Privilege Use                | Sensitive Privilege Use / Non Sensitive Privilege Use | Special privileges assigned to new logon. | 7045                        |                  1 | System                |  Security System Extension | A new service was installed by the user indicated in the subject |
| THEBORG       | 4672                               | Nov 6 · 10:10:00.000 pm |                        34 | Privilege Use                | Sensitive Privilege Use / Non Sensitive Privilege Use | Special privileges assigned to new logon. | 7045                        |                  1 | System                |  Security System Extension | A new service was installed by the user indicated in the subject |

# Lateral Movement

### Correlation matching on `endpoint.name` enriched with Lookup data

```sql
| join 
SUCCESSFUL_LOGON = (
    dataSource.name='Windows Event Logs' 
    | filter winEventLog.id=4624
    | let winEventLog.id = string(winEventLog.id)
    | group count = count() by endpoint.name, winEventLog.id, timestamp = timebucket('10m')
    | lookup Category,Subcategory, "Message Summary" from WindowsSecurityAuditEvents.csv by Event_ID = winEventLog.id
),
NETWORK_ACCESS = (
    dataSource.name='Windows Event Logs' 
    | filter ( winEventLog.id = 5140 OR winEventLog.id = 5156 )
    | let winEventLog.id = string(winEventLog.id)
    | group count = count() by endpoint.name, winEventLog.id, timestamp = timebucket('10m')
    | lookup Category,Subcategory, "Message Summary" from WindowsSecurityAuditEvents.csv by Event_ID = winEventLog.id
) 
on endpoint.name, timestamp 
```

| endpoint.name | SUCCESSFUL_LOGON.winEventLog.id | timestamp               | SUCCESSFUL_LOGON.count | SUCCESSFUL_LOGON.Category | SUCCESSFUL_LOGON.Subcategory | SUCCESSFUL_LOGON.Message Summary       | NETWORK_ACCESS.winEventLog.id | NETWORK_ACCESS.count | NETWORK_ACCESS.Category | NETWORK_ACCESS.Subcategory    | NETWORK_ACCESS.Message Summary                           |
| ------------- | ------------------------------- | ----------------------- | ---------------------: | ------------------------- | ---------------------------- | -------------------------------------- | ----------------------------- | -------------------: | ----------------------- | ----------------------------- | -------------------------------------------------------- |
| THEBORG       | 4624                            | Oct 31 · 4:40:00.000 pm |                     35 | Logon/Logoff              | Logon                        | An account was successfully logged on. | 5156                          |                    6 | Object Access           | Filtering Platform Connection | The Windows Filtering Platform has allowed a connection. |
| THEBORG       | 4624                            | Nov 1 · 8:40:00.000 am  |                     36 | Logon/Logoff              | Logon                        | An account was successfully logged on. | 5156                          |                    6 | Object Access           | Filtering Platform Connection | The Windows Filtering Platform has allowed a connection. |
---

# Data Exfiltration

### Correlation matching on `endpoint.name` enriched with Lookup data

```sql
| join 
DATA_ACCESS = (
    dataSource.name='Windows Event Logs' 
    | filter ( winEventLog.id = 4663 OR winEventLog.id = 4985 )
    | let winEventLog.id = string(winEventLog.id)
    | group count = count() by endpoint.name, winEventLog.id, timestamp = timebucket('10m')
    | lookup Category,Subcategory, "Message Summary" from WindowsSecurityAuditEvents.csv by Event_ID = winEventLog.id
),
NETWORK_ACCESS = (
    dataSource.name='Windows Event Logs' 
    | filter ( winEventLog.id = 5140 OR winEventLog.id = 5156 )
    | let winEventLog.id = string(winEventLog.id)
    | group count = count() by endpoint.name, winEventLog.id, timestamp = timebucket('10m')
    | lookup Category,Subcategory, "Message Summary" from WindowsSecurityAuditEvents.csv by Event_ID = winEventLog.id
) 
on endpoint.name, timestamp
```

| endpoint.name | DATA_ACCESS.winEventLog.id | timestamp               | DATA_ACCESS.count | DATA_ACCESS.Category | DATA_ACCESS.Subcategory | DATA_ACCESS.Message Summary             | NETWORK_ACCESS.winEventLog.id | NETWORK_ACCESS.count | NETWORK_ACCESS.Category | NETWORK_ACCESS.Subcategory    | NETWORK_ACCESS.Message Summary                           |
| ------------- | -------------------------- | ----------------------- | ----------------: | -------------------- | ----------------------- | --------------------------------------- | ----------------------------- | -------------------: | ----------------------- | ----------------------------- | -------------------------------------------------------- |
| THEBORG       | 4985                       | Oct 31 · 4:40:00.000 pm |               306 | Object Access        | File System             | The state of a transaction has changed. | 5156                          |                    6 | Object Access           | Filtering Platform Connection | The Windows Filtering Platform has allowed a connection. |
| THEBORG       | 4985                       | Nov 1 · 8:40:00.000 am  |               306 | Object Access        | File System             | The state of a transaction has changed. | 5156                          |                    6 | Object Access           | Filtering Platform Connection | The Windows Filtering Platform has allowed a connection. |
---
