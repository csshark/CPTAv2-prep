Attacks in case of basic detection rules and fundamentals of [[Blue Team]]ing.

[[#1. Tools]]

Overall tip for recon: 
![[nmap.png]]
There are a few expoits/attacks possible. Common vulnerable ports: 
- **Ports 137 and 139 (NetBIOS over TCP) and 445 (SMB)**
- **Port 22 (SSH)**
- **Port 21 (FTP)**
- **Port 53 (DNS)**
- **Port 25 (SMTP)**
- **Port 3389 (remote desktop)**
- **Ports 80, 443, 8080 and 8443 (HTTP and HTTPS)**
- **Ports 20 and 21 (FTP)**
- **Port 23 (Telnet)**
- **Ports 1433, 1434 and 3306 (used by databases)**

Almost all of mentioned above is included in CPTAv2 Labs ad is further exploited. 
# 1. Tools 

1. We gonna need Nmap/NmapAutomator, this command is ur bestie:
```
nmap -Pn <target>
```
 *Blue Tip:* when running TCP SYN Nmap **scan** remember about SYN=1 and RST=1. 
2. **enum4linux** 
```
enum4linux -a <target> 
```
*Blue Tip:* enum4linux generates a TCP request over the destination port 139,137,445
3. **msfconsole** - basically if some of ports is open find CVE and execute it.
*Blue Tip:* **FTP** requests are generally use traditional TCP: SYN | SYN/ACK | RST  request method to establish a reliable connection over the destination (port 21)
*Blue Tip:* **SSH** requests are generally use traditional TCP: SYN | SYN/ACK | RST request method to establish a reliable connection over the destination in addition with Key Exchange and Encryption for secure communication. Port 22.
*Blue Tip:* A **Telnet** client initiates a connection to a Telnet server on port 23, Unlike SSH, which encrypts all data, Telnet transmits all data, including usernames, passwords, and commands, in plain text. using traditional TCP: SYN | SYN/ACK request method to establish a reliable connection over the destination. Port **3306**.
*Blue Tip:* **VNC** served on port 5900. VNC protocol involves a client  
and a server and that will operate over any reliable transport such as TCP/IP using traditional TCP: SYN | SYN/ACK | ACK. So we go with rule **port.dst == 5900**
4. **Wimpeas → Windows Privilege Escalation Awesome Scripts** 
*Blue Tip:* Winpeas request multiple windows command to retrieve whole lot of information from the host, when  
we are executing Winpeas, it typically generate a events with event id 4103 command is invoked via PowerShell
5. **BurpSuite** - for all web application attacks such as SQLI, Path Traversal, PHP etc. Daily used tool, no need to explain more. 
6. Not tool, but command: `find / -perm -u=s -type f 2>/dev/null` it's for SUID. Visit website https://gtfobins.github.io/ and check if you can bypass local security restrictions. Used for ssh connection security restrictions bypass. If you have access to Windows based system go to https://lolbas-project.github.io/# instead. 