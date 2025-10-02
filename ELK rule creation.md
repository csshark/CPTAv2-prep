Where? Security -> Alerts and then navigate to Rules. Next Click "Create rule" button. 

Before digging into rule creation there is also a dedicated resource worth a shot, it might help implement ready to use rules into Elastic:
https://elastic.github.io/detection-rules-explorer/. 

Here I am gonna go trough all the parameters for rule creation in ELK Stack with Wazuh. All parameters are described when, how and which to use for specific attack type.

## rule id (3000-39999)
This rule id range is based on Windows detection rules.

```
<rule id="33120"> # example rule for Windows authentication events category
```
## level 
There is `<rule id="33120" level="3">` syntax. The level means **severity**. Here is severity range:
- 0-2: System/Informational events
- 3-6: Low/Medium security events
- 7-10: High severity alerts
- 11-15: Critical/emergency alerts
## <if_sid>
This is additional rule for context of the events. This rule ONLY triggers if parent rule 60103 also matches:
```
<if_sid>60103</if_sid>
```
## fields
This syntax is the most confusing, but it actually makes a lot of sense. Let's check on rule matching special privileges Windows Event ID (see: [[WindowsEventID - CPTAv2]]):
```
<field name="win.system.eventID">^4672$</field>
```

Syntax looks absurd, but here is the magic behind all chars: 
- `^` = start of string
- `4672` = exact Event ID
- `$` = end of string
So when a user logs in with administrative privileges the rule triggers!
## options 
Here we can pass a lot of additional functions let's see `<options>no_full_log</options>` - it prevents storing the full raw log in alerts. Usually there is used also *throttled* option, but no_full_log is gonna be used 90% of the time. 

## description
The place where operator puts information what actually happened. It can be 
```
<description>Login from external IP Address.</description>
```


# Common Patterns
CPTAv2 Labs related.
```
// Any admin share access
share.name: "*$" and not source.ip: "127.0.0.1"

// Any service installation  
event.code: 4697 or event.code: 7045

// Any scheduled task
event.code: 4698 or event.code: 4700

// Any Kerberos attack
ticket.encryption_type: "0x17" or kerberos.pre_authentication_type: 0
```