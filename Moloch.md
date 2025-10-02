filter via: ip.src == < ip addr here > 

Here is the list of useful filters to find anomalies:
```
# WMI traffic
protocol == dcerpc && service == 135

# SMB patterns
protocol == smb && smb.command == 0x75

# for kerberoasting attacks
protocol == kerberos && kerberos.msg_type == "TGS-REQ"

# for large transfers
bytes > 5000000
```