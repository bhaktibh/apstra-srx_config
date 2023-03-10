#!/usr/bin/python
import requests, os
import json, ipaddress
import re,sys
import socket,pwinput
import yaml
import glob
from pprint import pprint
from jinja2 import Environment, FileSystemLoader
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def apstra_auth_token(aos_url, aos_user, aos_password):
    tokenreq_body={'username':aos_user,'password':aos_password}
    req_header={'accept':'application/json','content-type':'application/json'}
    token_res=requests.post(f"{aos_url}/api/aaa/login",headers=req_header,json=tokenreq_body,verify=False)
    authtoken=''
    try:
        authtoken=token_res.json()['token']
    except Exception as e:
        sys.exit("Authentication failed. Username and password for Apstra could be wrong.")
        
    return authtoken

def get_blueprint_id(aos_url, token):
    headers={'AuthToken':token}
    
    #Step 1 - Pull all defined blueprints
    blueprintlist=requests.get(f'{aos_url}/api/blueprints',headers=headers,verify=False)
    bpid = ''
    for blueprint in blueprintlist.json()['items']:
        if blueprint['label'] == aos_blueprint:
            bpid=blueprint['id']
    
    if bpid == '':
        sys.exit("blueprint name provided is wrong. Please verify name on Apstra UI.")
        
    return bpid

def get_bp_nodes(aos_url, token,bp_id):
    headers={'AuthToken':token}

    #Step 2 - Pull all nodes
    bp_systems=requests.get(f'{aos_url}/api/blueprints/{bp_id}/nodes?node_type=system',headers=headers,verify=False)
    
    # parse json in place to get only leaf nodes based on roles key
    systems=bp_systems.json()['nodes']
    nodes_list = [[system['id'],system['hostname'],system['role']] for key,system in systems.items() if system['role'] == 'leaf' or system['role'] == 'spine']
    
    if nodes_list is None or nodes_list == []:
        sys.exit("Blueprint doesnt contain any leaf nodes or there is other issue. Please verify Blueprint name on Apstra")
    return nodes_list

def get_device_context(aos_url,token,bp_id,node_id):
    headers={'AuthToken':token}
    #Step 2 - Pull all nodes
    resp=requests.get(f'{aos_url}/api/blueprints/{bp_id}/nodes/{node_id}/config-context',headers=headers,verify=False)
    
    #print (resp.json()['context'])
    
    device_context = resp.json()
    #print(type(device_context))
    #device_context_formatted = json.dumps(device_context, indent=2)
    #print(type(device_context_formatted))
    return device_context

if __name__ == "__main__":
    # Validate Input
    while True:
        aos_ip = input("Enter Apstra IP. Ensure there is connectivity towards Apstra IP: ")
        try:
            valid_ip = ipaddress.ip_address(aos_ip)
            bytes = aos_ip.split(".")
            #print (bytes)
            if (int(bytes[0])) == 255:
                raise ValueError
            for ip_byte in bytes:
                if int(ip_byte) < 0 or int(ip_byte) > 255:
                    raise ValueError
        except ValueError:
            print("Enter valid IP")
            continue
        else:
            break
    while True:
        aos_port = input("Enter https port if different to 443: ")
        if aos_port != "":
            try:
                if 1 <= int(aos_port) <= 65535:
                    print("This is a VALID port number.")
                else:
                    raise ValueError
            except ValueError:
                print("NOT a VALID port number.")
        else:
            break
    aos_user = input("Enter apstra username. if admin then press Enter: ")
    print("Enter apstra password")
    aos_password=pwinput.pwinput()
        
    while True:
        aos_blueprint = input("Enter Blueprint Name as shown in Apstra: ")
        try:
            if aos_blueprint == "":
                raise ValueError
        except ValueError:
            print("Enter valid blueprint from Apstra")
            continue
        else:
            break
    
    # Aos url
    if aos_port != "":
        aos_url = "https://"+ aos_ip + ":" + str(aos_port)
    else:
        aos_url = "https://"+ aos_ip
        
    
    if aos_user == "":
        aos_user = "admin"
        
    # Next get auth token by logging into Apstra
    token = apstra_auth_token(aos_url, aos_user, aos_password)
    #print ("Token is ", token)
    # Next get blueprints and parse to get blueprint ID
    bp_id = get_blueprint_id(aos_url, token)
    print ("Blueprint found.")
    # Next get leaf and spine nodes from Blueprint
    bp_nodes = get_bp_nodes(aos_url, token,bp_id)
    print ("Blueprint Nodes found")
    #print ('Nodes are ', bp_nodes)
    node_id=''
    
    srx_bgp = []
    srx_bgp_session = []
    srx_lpbck_addr = []
    leaf_node_found = False

    #write config generated below to srx config file
    THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    #srx_config_f = open("srx_config.txt", "w")
    fileList = glob.glob('srx_config_*.txt')
    if fileList != []:
        for filePath in fileList:
            try:
                os.remove(filePath)
            except:
                pass
    srx_count = 0
    spine_node = []
    if bp_nodes != []:
        for node in bp_nodes:
            prev_spine=''
            if node[2] == 'spine':
                # Getting spine device context
                device_context = get_device_context(aos_url,token,bp_id,node[0])
                context=[]
                context=json.loads(device_context['context'])
                bgp_sessions= context['bgp_sessions']
                # Get SRX BGP sessions from spine device context and collate it in srx_bgp from all spines
                for key,bgp in bgp_sessions.items():
                    if 'srx' in bgp['description']:
                        bgp["spine"] = node[1]
                        srx_bgp.append(bgp)
                spine_node.append(node[1])
                srx_count = len(srx_bgp)
                srx_lpbck_addr = [srx_bgp[i]['dest_ip'] for i in range(srx_count)]
        #removing duplicates 
        srx_lpbck_addr = set(srx_lpbck_addr)
        srx_lpbck_addr = list(srx_lpbck_addr)
        #create protocols template from protocols jinja
        protocol = Environment(loader=FileSystemLoader(THIS_DIR),
                      trim_blocks=True, lstrip_blocks=True)
        bgp_config = protocol.get_template('protocols.j2').render(
        #                 spine = node[1], srx_bgp = srx_bgp
                         srx_bgp = srx_bgp
        )
        #Now write file for srx_config
        for i in range(len(srx_lpbck_addr)):
            if os.path.isfile("srx_config_" + srx_lpbck_addr[i] + ".txt"):
                srx_filenm = open("srx_config_" + srx_lpbck_addr[i] + ".txt","a")
            else:
                print ("Adding protocols bgp to srx_config_"+ srx_lpbck_addr[i]+ ".txt")
                srx_filenm = open("srx_config_" + srx_lpbck_addr[i] + ".txt","w")
            try:
                srx_filenm.write(bgp_config)
                srx_filenm.write('\n')
            except Exception as e:
                sys.exit("File " + "srx_config_" + srx_lpbck_addr[i] + ".txt write error. In case if file is open then close file.")
        prev_spine = node[2]
        node=''
        for node in bp_nodes:
            if node[2] == 'leaf':
                leaf_node_found = True
                break

        device_context = get_device_context(aos_url,token,bp_id,node[0])
        context=[]
        context=json.loads(device_context['context'])
        rt_instances= context['security_zones']
        for r in range (len(srx_lpbck_addr)):
            rt_inst_config = protocol.get_template('routing_instances.j2').render(
                      local_addr = srx_lpbck_addr[r], rt_instances = rt_instances
            )
            #print (output)
            policy_op_config = protocol.get_template('policy-options.j2').render(
                      rt_instances = rt_instances
            )
            #lldp_config = protocol.get_template('protocols_lldp.j2').render()
            #print (output)
            print ("Adding protocols lldp, routing_instances, policy_options to srx_config_"+ srx_bgp[i]['dest_ip']+ ".txt")
            srx_filenm = open("srx_config_" + srx_lpbck_addr[r] + ".txt","a")
            try:
                #srx_filenm.write('\n')
                #srx_filenm.write(lldp_config)
                srx_filenm.write('\n')
                srx_filenm.write(rt_inst_config)
                srx_filenm.write('\n')
                srx_filenm.write(policy_op_config)
                srx_filenm.close()
            except Exception as e:
                sys.exit("File " + "srx_config_" + srx_lpbck_addr[r] + ".txt write error. In case if file is open then close file.")
    #Lets check if the file got generated again and print message
    fileList = glob.glob('srx_config_*.txt')
    if fileList != []:
        for filePath in fileList:
            print ('SRX config file generated for', filePath)
    else:
        print ('SRX config file not generated at all! Something went wrong..:(')