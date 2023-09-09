#!/usr/bin/env python
## https://github.com/corey-braun/google-api-ips
## Finds IP ranges used for google APIs & services in CIDR notation, then writes them to a file and/or creates/updates OPNsense FW alias with the IPs.
## See https://support.google.com/a/answer/10026322 for info on the Google API IP ranges this script collects.

import sys
import yaml
import logging
import requests
from netaddr import IPNetwork, IPSet

def main():
    alias_ips = get_google_ips()
    if config['create_ips_file']:
        with open(config['ips_file_name'],'w+') as f:
            f.write("\n".join(alias_ips))
        logging.info(f"Wrote API IPs to file '{config['ips_file_name']}'")
    if config['update_fw_alias']:
        update_alias(alias_ips)
    if not (config['create_ips_file'] or config['update_fw_alias']):
        for i in alias_ips:
            print(i)

def get_config(config_file_name='config'):
    default_config = {
        'log_file': '/tmp/googleips.log',
        'log_level': 'INFO',
        'all_google_ips_url': 'https://www.gstatic.com/ipranges/goog.json',
        'google_cloud_ips_url': 'https://www.gstatic.com/ipranges/cloud.json',
        'create_ips_file': False,
        'ips_file_name': 'google-api-ips.txt',
        'update_fw_alias': True,
        'fw_check_cert': True,
        'fw_url': None,
        'fw_api_key': None,
        'fw_api_secret': None,
        'alias_name': 'Google_API_Alias'
    }
    config_path = sys.path[0]
    if len(config_path) > 0:
        config_path += '/'
    user_config = read_yaml(config_path + config_file_name)
    return default_config | user_config

def read_yaml(filename):
    for file in [f'{filename}.yaml', f'{filename}.yml', filename]:
        try:
            with open(file) as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            pass
    sys.exit(f"Failed to find {filename} yaml file")

def logging_setup():
    log_level = getattr(logging, config['log_level'].upper(), None)
    if not isinstance(log_level, int):
        raise ValueError(f"Invalid log level: {config['log_level']}")
    logging.basicConfig(
        format='%(asctime)s %(levelname)s - %(message)s',
        datefmt='%Y-%d-%m %H:%M:%S',
        level=log_level,
        filename=config['log_file']
    )

def get_google_ips():
    """Get list of CIDR-notation Google subnets not assigned to GCP customers (and therefore used for google's APIs and services)"""
    logging.debug('Getting Google API IPs')
    all_ips = get_ip_set(config['all_google_ips_url'])
    customer_ips = get_ip_set(config['google_cloud_ips_url'])
    api_ips = all_ips - customer_ips
    return [str(x) for x in api_ips.iter_cidrs()]

def get_ip_set(url):
    try:
        json_data = requests.get(url).json()
    except:
        logging.exception(f"Error getting JSON data from '{url}'")
        raise
    try:
        return IPSet([next(iter(i.values())) for i in json_data['prefixes']])
    except:
        logging.exception(f"Error adding CIDR blocks to IPSet")
        raise

def update_alias(ip_list):
    logging.debug("Updating firewall alias")
    alias_lookup = fw_api_call('GET', f"api/firewall/alias/getAliasUUID/{config['alias_name']}")
    try:
        uuid = alias_lookup['uuid']
    except (TypeError, KeyError):
        logging.debug(f"Alias '{config['alias_name']}' does not exist, creating it.")
        url = 'api/firewall/alias/addItem/'
        alias_action = 'create'
    else:
        alias_content = fw_api_call('GET', f"api/firewall/alias/getItem/{uuid}")
        current_alias_ips = [x['value'] for x in alias_content['alias']['content'].values() if x['selected'] == 1]
        if current_alias_ips == ip_list:
            logging.info(f"Alias '{config['alias_name']}' already up to date.")
            sys.exit()
        logging.debug(f"Alias '{config['alias_name']}' already exists, updating it.")
        url = f'api/firewall/alias/setItem/{uuid}'
        alias_action = 'update'
        #for i in alias_content['alias']['content']:
        #    if i['selected'] == 1:
        #        current_alias_ips.append(i['value'])
    payload = {'alias':{'name':config['alias_name'],'type':'network','enabled':'1','content':"\n".join(ip_list)}}
    alias_update = fw_api_call('POST', url, payload)
    #if not alias_update['result'] == 'saved':
    #    err = f"Failed to {alias_action} alias '{config['alias_name']}'. API Response: {alias_update}"
    #    logging.error(err)
    #    sys.exit(err)
    logging.debug("Applying alias changes.")
    alias_apply = fw_api_call('POST', 'api/firewall/alias/reconfigure')
    logging.info(f"Alias '{config['alias_name']}' {alias_action}d with {len(ip_list)} CIDR blocks.")

def fw_api_call(http_method, api_endpoint, json_payload=None):
    try:
        r = requests.request(
            http_method,
            f"{config['fw_url']}{api_endpoint}",
            auth=(config['fw_api_key'], config['fw_api_secret']),
            verify=config['fw_check_cert'],
            json=json_payload
        )
        r.raise_for_status()
        try:
            if r.json()['result'] == 'failed':
                raise APIResponseError("API call failed.")
        except KeyError:
            pass
        return r.json()
    except:
        if json_payload:
            data_err=f" with data '{json_payload}'"
        else:
            data_err=""
        try:
            response_err=f" API Response: '{r.text}'."
        except:
            response_err=""
            pass
        logging.exception(f"Failed to make {http_method} API call to endpoint '{api_endpoint}'{data_err}. HTTP Status Code: {r.status_code}.{response_err}")
        raise

class APIResponseError(Exception):
    pass

config = get_config()
logging_setup()

if __name__ == "__main__":
    main()
