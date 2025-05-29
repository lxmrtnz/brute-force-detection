# Incident Response: Brute force attack

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- SIEM Platform: Microsoft Sentinel
- Kusto Query Language (KQL)

##  Scenario

The security team detected a spike in failed login attempts from several remote IPs targeting multiple devices and accounts. This may indicate a brute force attack. Using Microsoft Sentinel and KQL, the team must identify suspicious IPs and accounts with repeated failures to investigate and respond quickly.

### High-Level Brute Force Detection Plan

- **Using `DeviceLogonEvents`** Design a Sentinel Scheduled Query Rule within Login Analytics that will discover when the same remote IP address has failed to log in to the same local host (Azure VM) 1500 times or more within the last 5 hours
- **Check `DeviceLogonEvents`** for any signs of a successfull login

---

## Steps Taken

### 1. Create the Alert Rule (Brute Force Attempt Detection)
Created the Alert rule in Microsoft Sentinel and set Mitre ATT&CK Framework categories based on the query. This rule will be set to automatically create an incident if the rule is triggered.

**Mitre ATT&CK Framework Categories**
```
T1110 Brute Force
T1110.001 Password Guessing
T1110.002 Pasword Cracking
T1087 Account Discovery
T1087.001 Local Account
```

<img width="1212" alt="image" src="https://github.com/user-attachments/assets/6512fc8f-9573-4d82-bdc7-1ff62963460e">

**Query used to locate events:**

```kql
let FailedLogons = DeviceLogonEvents
    | where ActionType == "LogonFailed"
    | where TimeGenerated >= ago(5h)
    | project TimeGenerated, RemoteIP, DeviceName, AccountName, ActionType;

FailedLogons
| join kind=inner FailedLogons on RemoteIP, DeviceName
| where TimeGenerated1 between (TimeGenerated .. TimeGenerated + 5h)
| summarize Attempts = count() by RemoteIP, DeviceName, ActionType
| where Attempts >= 1500
| project RemoteIP, DeviceName, ActionType, Attempts  
| order by Attempts desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/3fd2c2c0-b2be-4b61-9e66-0506bda5c5b0">

### 2. Gather relivant evidence and assess impact


