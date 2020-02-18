#!/usr/bin/env python3

import os
import sys
import json
import urllib3
#import inquirer
import re
import argparse
import configparser
import requests
from proxmoxer import ProxmoxAPI

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

s = requests.Session()
s.headers.update({'Accept': 'application/xhtml+xml'})
s.verify = False

# argparser
parser = argparse.ArgumentParser(description='Creates yaml file for Wiki import')
parser.add_argument('-v', '--verbose', help='debugging mode', action='store_true')
parser.add_argument('-p', '--print', help='print all ')
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
vms = {}
vms['nodes'] = {}
for config in config_data:
    try:
        api = ProxmoxAPI(config.get('ip'), user = config.get('user'), password = config.get('pwd'), verify_ssl = False)
        for node in api.nodes.get():
            node_name = node.get('node')
            vms['nodes'][node_name] = {}
            vms['nodes'][node_name]['vms'] = {}
            node_vms = api.nodes(node_name).get('qemu')
            print ('Node ----->' + node_name)
            for vm in node_vms:
                vm_id = vm.get('vmid')
                vm_name = vm.get('name')
                vm_status = vm.get('status')
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
                            ip_type = ip.get('ip-address-type')
                            #print (ip_address)
                            if ip_address != '127.0.0.1' and ip_address != '::1' and not None and ip_type == 'ipv4':
                                vm_ip.append(ip_address)
                except:
                    if vm_status == "stopped":
                        vm_ip = 'stopped'
                    else:
                        vm_ip = 'qemu agent not installed'
                vms['nodes'][node_name]['vms'][vm_name] = {}
                vms['nodes'][node_name]['vms'][vm_name]['vm_id'] = vm_id
                vms['nodes'][node_name]['vms'][vm_name]['vm_name'] = vm_name
                vms['nodes'][node_name]['vms'][vm_name]['vm_ips'] = {}
                vms['nodes'][node_name]['vms'][vm_name]['vm_ips'] = vm_ip
                vms['nodes'][node_name]['vms'][vm_name]['vm_node'] = node_name
                print ("Adding:" + node_name, vm_id, vm_name, vm_ip)
                
    except EnvironmentError as e:
        print (e)

if args['verbose']:
    print ('JSON Output: \n' + str(vms))


json_vms = json.dumps(vms)
with open('vms.json', 'w') as f:
    json.dump(vms, f)

