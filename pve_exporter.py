#!/usr/bin/env python3

import os
import sys
import json
import urllib3
import inquirer
import re
from tabulate import tabulate
import argparse
import configparser
import getpass
import requests
from proxmoxer import ProxmoxAPI

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

s = requests.Session()
s.headers.update({'Accept': 'application/xhtml+xml'})
s.verify = False

# argparser
parser = argparse.ArgumentParser(description='Creates yaml file for Wiki import')
parser.add_argument('-v', '--verbose', help='debugging mode', action='store_true')
args = vars(parser.parse_args())

# read config.ini
config = configparser.ConfigParser()
config_data = []
try:
    config.read('config.ini')
    for node in config.sections():
        config_data.append({'nodename': node,
                            'ip': config[node]['ip'],
                            'user': config[node]['user'],
                            'pwd': config[node]['passwd'] })
except:
    print ('no config')

# for debugging
if args['verbose']:
    print (config_data)

# populate vms pool
vms = []
for config in config_data:
    try:
        api = ProxmoxAPI(config.get('ip'), user = config.get('user'), password = config.get('pwd'), verify_ssl = False)
        for node in api.nodes.get():
            node_name = node.get('node')
            node_vms = api.nodes(node_name).get('qemu')
            #print (node_name)
            for vm in node_vms:
                vm_id = vm.get('vmid')
                vm_name = vm.get('name')
                vm_ip = []
                try:
                    vm_agent = api.nodes(node_name).qemu(vm_id).agent()
                    vm_ifs = vm_agent.get('network-get-interfaces').get('result')
                    #print (vm_ifs)
                    for vm_if in vm_ifs:
                        vm_ips = vm_if.get('ip-addresses')
                        #print (vm_ips)
                        for ip in vm_ips:
                            ip_address = ip.get('ip-address')
                            #print (ip_address)
                            if ip_address != '127.0.0.1' and ip_address != '::1' and not None:
                                vm_ip.append(ip_address)
                except:
                    vm_ip = 'qemu agent not installed'
                               
                print ("Adding:" + node_name, vm_id, vm_name, vm_ip)
                vms.append({node_name, vm_id, vm_name,})
    except EnvironmentError as e:
        print (e)

print (vms)
#json_vms = json.dumps(vms)
#with open('vms.json', 'w') as f:
#    json.dump(json_vms, f)

