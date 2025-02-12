
# Description

Joomla! 3.7.0 SQLi PoC

This script checks the target Joomla! version. If the target is vulnerable, it can exploit the vulnerability to dump the first user's username, email, and password from the Joomla database. 

Feel free to use and adapt the code however you like.

More details about the vulnerability
- [CVE-2017-8917](https://nvd.nist.gov/vuln/detail/CVE-2017-8917)
- https://blog.sucuri.net/2017/05/sql-injection-vulnerability-joomla-3-7.html
# Usage

```
usage: joomla_3-7-0_sqli.py [-h] -u URL [-c]

Joomla! 3.7.0 SQLi via "com_fields" parameter

options:
  -h, --help         show this help message and exit
  -u URL, --url URL  The URL to the Joomla! webserver
  -c, --check        Checks if given URL is vulnerable
```

<img width="436" alt="image" src="https://github.com/user-attachments/assets/b43ad673-7640-4ca5-a952-7ef2f06f3a93" />

# Credits

This code is a python3 version of the code in https://www.exploit-db.com/exploits/44227, with a few improvements, such as a way to check the Joomla! version running.
