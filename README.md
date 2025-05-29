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

### 1. Create the Alert Rule
Created the Alert rule **`Brute Force Attempt Detection - lxmrtnz`** in Microsoft Sentinel and set Mitre ATT&CK Framework categories based on the query. This rule will be set to automatically create an incident if the rule is triggered.

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

---

### 2. Gather relevant evidence
After creating the rule it was triggered instantly. The **`Brute Force Attempt Detection - lxmrtnz`** incident was triggered from 5 different IP addresses against 5 different hosts.

<img width="1212" alt="image" src="https://github.com/user-attachments/assets/0b5c3e47-69ac-4c3c-9387-ce0add64a920">

<img width="1212" alt="image" src="https://github.com/user-attachments/assets/15ba9b72-e5ec-4ef8-a113-d505d6e3a9cc">

---

### 3. Search `DeviceLogonEvents` for successful logins. 
Searched for any evidence where any of the IP's successfully breached any of the hosts. There were 87 instances where the brute force attack from RemoteIP **`10.0.0.8`** was successful on Host **`blue-programmatic-fix-drea.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`**.

However, upon further review, **`10.0.0.8`** was identified as an **`internal jump host (NAT gateway)`** shared across multiple systems and users.
The high number of failed login attempts followed by successful logins is a known pattern for this IP due to centralized authentication routing. As such, these events are attributed to normal user activity and considered a false positive in the context of brute-force detection.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where RemoteIP in ("10.0.0.8", "186.10.23.226", "193.37.69.105", "43.131.224.248", "183.179.77.58")
| where DeviceName in ("pham-edr", "abe-mde-est", "ishan-windows-p", "kuda-hunt", "blue-programmatic-fix-drea.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net",)
| where ActionType == "LogonSuccess"
```

<img width="1212" alt="image" src="https://github.com/user-attachments/assets/d3cf65cf-6509-49d4-a799-c5cef46ae655">

---

### Summary
Developed and deployed a custom analytic rule in Microsoft Sentinel named **`Brute Force Attempt Detection - lxmrtnz`**, designed to detect high-volume failed logon attempts from the same IP and device within a 5-hour timeframe. This rule is mapped to multiple MITRE ATT&CK techniques, including brute force and account discovery. Once active, the rule immediately generated an incident involving five external IPs targeting five internal hosts.

To assess the potential impact, I pivoted to **`DeviceLogonEvents`** and discovered 87 successful logins from RemoteIP **`10.0.0.8`** to the host **`blue-programmatic-fix-drea...cloudapp.net`***, raising concern for a successful brute-force compromise. However, deeper investigation revealed that **`10.0.0.8`** is a known **`internal NAT gateway (jump host)`**, frequently used for centralized authentication across environments. The spike in failed logons followed by successful authentication is a recognized and expected pattern due to its role in routing user traffic.

Based on this context, I determined that the alert was a false positive, and no malicious activity occurred. This case reinforced the importance of baselining internal infrastructure behavior to reduce noise in brute-force alerting logic.

---

### 4. Response Taken
- AV scan initiated across all impacted hosts using Microsoft Defender for Endpoint (MDE).
- Updated NSG configurations to block RDP access from public IP addresses.
- Proposed and submitted corporate policy revision to require all Azure VMs to disallow public-facing RDP unless explicitly justified and approved.

---





 


