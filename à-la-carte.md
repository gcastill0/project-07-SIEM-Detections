| Use Case | Pattern | Description |
|----------|---------|-------------|
| Multiple Discovery Commands Executed | Use audit logs from Windows and Linux systems to capture commands. Match command to privileged, administrative set. Evaluate the number of commands over a period of time. | Detect users executing a significant number of network and system discovery commands within a short time window. |
| Brute Force Attempt  |  Enumerate a threshold number of failed logging attemps, and one successul attempt, focusing on the same device. Evaluate over a period of time.  | Detects possible brute-force or credential-stuffing attacks by correlating multiple failed logons with a subsequent successful logon.  |
| Exploitation of Remote Services Detection  | Destination port matches 445 or 139 | Detects attempts to access SMB services over the internet, which may indicate misconfigurations or data exfiltration. (MITRE: T1021.002 – Remote Services: SMB/Windows Admin Shares) | 
| Suspicious Traffic on TOR Port | Destination port matches 9001, 9030, 9050, or 9051. | Identifies potential TOR usage by flagging traffic to common TOR relay or entry ports. (MITRE: T1090.003 – Proxy: Multi-hop Proxy) |

# Multiple Discovery Commands Executed

This use case targets early-stage reconnaissance behavior, where a user or process runs a series of discovery commands to enumerate system, user, and network information. By analyzing audit logs from both Windows and Linux systems, the detection focuses on identifying a burst of administrative or system-level commands executed in a short time frame — often a precursor to lateral movement or privilege escalation.

The following is a list of common commands for consideration for Windows or Linux.

| Windows                   | Linux                                      |
| ------------------------- | ------------------------------------------ |
| `ipconfig`                | `ip a` or `ifconfig` (deprecated)          |
| `dnscmd`                  | `resolvectl` or `dig` or `systemd-resolve` |
| `Get-ChildItem`           | `ls -l`                                    |
| `cmd.exe /c dir`          | `ls`                                       |
| `Get-NetTCPConnection`    | `ss -tuna` or `netstat -tuna`              |
| `Tasklist`                | `ps aux`                                   |
| `Get-Process`             | `ps -e` or `top`                           |
| `Whoami`                  | `whoami`                                   |
| `id`                      | `id`                                       |
| `Systeminfo`              | `uname -a && lsb_release -a`               |
| `procinfo`                | `cat /proc/cpuinfo` or `ps -p PID`         |
| `lscpu`                   | `lscpu` *(native)*                         |


## Monitoring via Audit Logs from Windows

Enable Command Line Process Auditing (via Group Policy or Local Security Policy)

This method uses **Windows built-in auditing** to log when processes are created **with full command-line arguments**, which gives you visibility into commands like `ipconfig`, `cmd.exe /c dir`, `Get-Process`, etc.

#### Steps:

1. Open **Local Group Policy Editor** (`gpedit.msc`)

2. Navigate to:

   ```
   Computer Configuration → Administrative Templates → System → Audit Process Creation
   ```

3. Enable:

   * **Include command line in process creation events**

4. Open **Local Security Policy** (`secpol.msc`):

   ```
   Security Settings → Advanced Audit Policy Configuration → System Audit Policies → Detailed Tracking
   ```

5. Enable:

   * **Audit Process Creation**

## Monitoring via Sudo Logs from Linux

To log the use of privileged commands like sudo, you can enhance auditing in `/etc/sudoers` by using the `log_input`, `log_output`, and logfile options. These enable command logging with input/output  capture.

You should not modify the main file directly — instead, the  recommended way on Linux is to add a file under `/etc/sudoers.d/ using visudo`.

1. Create a log file
   ```bash
   sudo touch /var/log/sudo.log
   sudo chown root:adm /var/log/sudo.log
   ```

2. Create a new file safely with visudo

   ```bash
   sudo visudo -f /etc/sudoers.d/logging
   ```

3. Add logging directives

   ```bash
   Defaults log_input
   Defaults log_output
   Defaults logfile="/var/log/sudo.log"
   ```

## Monitoring via `auditd` from Linux

On Linux, the best and most secure way to audit all user commands is to enable auditd and configure it to log command execution, including via `execve`, along with `sudo`, `su`, and shell sessions.

4. Create a log file
   ```bash
   sudo apt update
   sudo apt install -y auditd audispd-plugins
   ```

5. Create a new file safely with visudo

   ```bash
   sudo systemctl enable --now auditd
   ```

## Windows Detections

**Program Execution: Basic Filter**

Capture the execution of suspicious or dual-use administrative tools often seen in scripted reconnaissance or exploitation chains. This includes tools like bcedit (boot config), mshta (HTA scripting), and powershell.

```sql
dataSource.name='Windows Event Logs' 
winEventLog.providerName='Microsoft-Windows-Security-Auditing' 
winEventLog.data.event.eventData.processName contains:anycase ( 'bcedit', 'mshta', 'powershell' )
```

**Program Execution: Enumeration**

Count the number of times specific programs are executed within a timeframe. Helps detect clustering behavior — a burst of tool usage — indicative of automated discovery or attacker hands-on-keyboard activity.

```sql
dataSource.name='Windows Event Logs' 
winEventLog.providerName='Microsoft-Windows-Security-Auditing' 
winEventLog.channel='Security'
| filter NOT isempty( winEventLog.data.event.eventData.processName )
| parse "(.+?\\\\){1,}$process_name{regex=[a-zA-Z0-9\.]+}$" from winEventLog.data.event.eventData.processName
| group count = count() by winEventLog.data.event.eventData.processName, process_name
```

**Command Execution: Basic Filter**

Identify the execution of well-known Windows discovery commands such as `ipconfig`, `systeminfo`, and `tasklist`. These are often executed together during internal reconnaissance by adversaries or post-exploitation frameworks.

```sql
dataSource.name = 'Windows Event Logs'
winEventLog.providerName='Microsoft-Windows-Security-Auditing'
winEventLog.id = 4688 winEventLog.data.event.eventData.newProcessName contains:anycase ( 'ipconfig', 'dnscmd', 'Get-ChildItem', 'Get-NetTCPConnection', 'Tasklist', 'Get-Process', 'Whoami', 'Systeminfo' )
```

**Command Execution: Enumeration**

Aggregate command executions by user over 5-minute windows to detect bursts of enumeration commands. This view helps isolate reconnaissance activity and tie it to specific user accounts for investigation or threat hunting.

```sql
dataSource.name = 'Windows Event Logs' winEventLog.id = 4688 
| filter winEventLog.data.event.eventData.newProcessName contains:anycase ( 'ipconfig', 'dnscmd', 'Get-ChildItem', 'Get-NetTCPConnection', 'Tasklist', 'Get-Process', 'Whoami', 'Systeminfo' )
| parse "(.+?\\\\){1,}$process_name{regex=[a-zA-Z0-9\.]+}$" from winEventLog.data.event.eventData.newProcessName
| group commands = array_agg(process_name) by timestamp = timebucket('5m'), user = winEventLog.data.event.eventData.subjectUserName
| let time = strftime(timestamp, "%Y-%m-%d %H:%M %Z")
| let executions = len(commands)
| columns time, commands, executions, user
```

## Linux Detections

**Basic filter**

Detect use of sudo, which can indicate privilege escalation attempts or administrative-level command execution. Capturing this is key to identifying misuse of elevated access.

```sql
parser = 'syslog' comm='sudo'
```

Flag execution of common Linux discovery utilities such as `ip`, `ps`, `id`, and `netstat`. These are used to survey host identity, users, interfaces, and active services.

```sql
parser = 'syslog' comm = * 
(comm contains:anycase ('ip', 'dig', 'ls', 'ps', 'netstat', 'id', 'systemctl' ) )
```

**Enumeration**: 

Group command usage by UID/GID within 5-minute intervals to detect abnormal spikes in discovery activity. This enables analysts to identify interactive shell behavior, credentialed enumeration, or scripted probing.

```sql
parser = 'syslog' comm = *
(comm contains:anycase ('ip', 'dig', 'ls', 'ps', 'netstat', 'id', 'systemctl' ) )
| group count = count() by uid = string(uid), gid = string(sgid), comm, timestamp = timebucket('5m')
```

# Brute Force Attempt

This use case identifies authentication abuse by detecting repeated failed logon attempts followed by a successful authentication on the same system. It correlates login activity over a defined window to reveal potential brute-force or credential-stuffing attacks, especially where an attacker may have eventually guessed or used a valid password. This behavior is often observed in early-stage compromise or during password reuse exploitation.

Using Windows Event logs, Event ID 4625 reflects multiple failed logon attempts. This must be assesed against Event ID 4624 successful logon.

Basic Filters: 

**Failed Attempts**: Captures failed Windows logon events, which occur when authentication attempts are rejected. These events are essential for identifying repeated failed access attempts that may indicate brute-force activity.
```sql
dataSource.name='Windows Event Logs' winEventLog.id=4625
```

**Successful Attempts**: Captures successful logons to the system. When correlated with earlier failed attempts, this helps detect potential password guessing or credential stuffing that eventually results in unauthorized access.

```sql
dataSource.name='Windows Event Logs' winEventLog.id=4624
```

**Correlation matching on `endpoint.name`**. Note we use a 10-minute window to match events over time. This query performs a time-windowed join on failed and successful logon events, grouped by endpoint.name within a 10-minute interval. The goal is to detect a pattern where:

- A high number of failed attempts occur on a device, and
- A successful logon follows shortly after, using the same host

This correlation reduces noise from isolated failed attempts and provides high-fidelity detection of brute-force patterns without requiring knowledge of the specific user account targeted.



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
