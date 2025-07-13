# bloodyIPA
bloodhound collector for freeIPA

Warning! Specific bloodhound branch required --> https://github.com/BloodHoundIPA/BloodHoundIPA

Requirements:
- python_freeipa
- Requests
- urllib3

```
usage: bloodyipa.py [-h] [-u USERNAME] [-k] [-p PASSWORD] [-dc HOST] [-v] [-use_ldap]
                    [-no_verify_certificate]

  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        Domain admin username
  -k, --kerberos        Use Kerberos for auth
  -p PASSWORD, --password PASSWORD
                        Domain admin password
  -dc HOST, --domain-controller HOST
                        DC hostname
  -v                    Enable verbose output
  -use_ldap             Collect objects from ldap
  -no_verify_certificate
                        No verify certificate
```