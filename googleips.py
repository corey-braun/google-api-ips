#!/bin/python3
## Finds IP ranges used for google APIs & services in CIDR notation, then writes them to a file and/or creates/updates OPNsense FW alias with the IPs.
## See https://support.google.com/a/answer/10026322 for info on google IP ranges.

from datetime import datetime
import requests
from netaddr import IPNetwork, IPSet

## Set default values for constants, import config to overwrite them.
ALL_GOOGLE_IPS_URL = 'https://www.gstatic.com/ipranges/goog.json'
GOOGLE_CLOUD_IPS_URL = 'https://www.gstatic.com/ipranges/cloud.json'
CREATE_IPS_FILE = False
UPDATE_FIREWALL = False
FW_CHECK_CERT = True
FW_URL = 'https://192.168.1.1/'
FW_API_KEY = ''
FW_API_SECRET = ''
ALIAS_NAME = 'Google_API_Alias'
from config import *


def main():
    print(datetime.now().strftime("%m/%d/%Y, %H:%M:%S"))
    print('Getting Google API IPs')
    alias_ips = get_google_ips() ## Get newline delimited list of Google IPs not assigned to cloud customers (used for google APIs and services)
    print('Done.', end='\n\n')
    if CREATE_IPS_FILE == True:
        print('Writing API IPs to file')
        (open('api-ips.txt','w+')).write(alias_ips)
        print('Done.', end='\n\n')
    if UPDATE_FIREWALL == True:
        print('Creating Firewall Alias')
        create_alias(alias_ips)
        print('Done.', end='\n\n')
        print ('Applying changes to Firewall Aliases.')
        apply_alias_changes()
        print('Done.')
    print()

def get_google_ips():
    all_google_ips = get_ip_set(ALL_GOOGLE_IPS_URL)
    google_customer_ips = get_ip_set(GOOGLE_CLOUD_IPS_URL)
    google_api_services_ips = (all_google_ips ^ google_customer_ips)
    api_ips_formatted = ''
    for ip in google_api_services_ips.iter_cidrs():
        if api_ips_formatted == '':
            api_ips_formatted = str(ip)
        else:
            api_ips_formatted = (api_ips_formatted + '\n' + str(ip))
    return api_ips_formatted

def get_ip_set(url):
    json_data = requests.get(url).json()
    prefixes_dicts_list = json_data['prefixes']
    ip_list = []
    for i in prefixes_dicts_list:
        ip_list.append(next(iter(i.values()))) ## Add the value of each dict's only key:value pair to the iplist
    return IPSet(ip_list)

def create_alias(content):
    payload = {'alias':{'name':ALIAS_NAME,'type':'network','enabled':'1','content':content}}
    r = requests.get((FW_URL + 'api/firewall/alias/getAliasUUID/' + ALIAS_NAME), auth=(FW_API_KEY, FW_API_SECRET), verify=FW_CHECK_CERT)
    try:
        uuid = (r.json())['uuid']
        print('Alias already exists, updating it.')
        post_path = (FW_URL + 'api/firewall/alias/setItem/' + uuid)
    except:
        post_path = (FW_URL + 'api/firewall/alias/addItem/' + ALIAS_NAME)
    r = requests.post(post_path, auth=(FW_API_KEY, FW_API_SECRET), json=payload, verify=FW_CHECK_CERT)
    print('Firewall response: ' + str(r.json()))

def apply_alias_changes():
    r = requests.post((FW_URL + 'api/firewall/alias/reconfigure'), auth=(FW_API_KEY, FW_API_SECRET), verify=FW_CHECK_CERT)
    print('Firewall response: ' + str(r.json()))

if __name__ == "__main__":
    main()
