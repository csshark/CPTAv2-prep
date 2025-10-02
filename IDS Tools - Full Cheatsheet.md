Basically its only network support for ELK Stack, so the most important thing is to make it count by creating IDS rule 

suricata/IDS rule example: 
```
alert tcp External any -> any 445 (msg:"Suspicious WinRM Communication observed ";  
sid:100011; priority: 7;)
```
