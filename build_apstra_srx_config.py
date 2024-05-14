#!/usr/bin/python
import requests, os
import inquirer
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

def get_blueprints(aos_url, token):
    headers={'AuthToken':token}
    
    #Step 1 - Pull all defined blueprints
    blueprintlist=requests.get(f'{aos_url}/api/blueprints',headers=headers,verify=False)
    #get_user_blueprint_id()
    bplist=[]
    for blueprint in blueprintlist.json()['items']:
            bplist.append({'label':blueprint['label'],'id':blueprint['id']})
    return bplist

def get_user_blueprint_id():
    bpid = ''
    #Step 1 - Pull all defined blueprints
    headers={'AuthToken':token}
    blueprintlist=requests.get(f'{aos_url}/api/blueprints',headers=headers,verify=False)
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
    return device_context

#def build_srx_conf(srx_bgp,srx_lpbck_addr,):
#    spine_srx_data = []
#    if srx_bgp != [] :
#        for i in range(len(srx_lpbck_addr)):
#            spine_srx_data = []
#            for bgp_data in srx_bgp:
#                if srx_lpbck_addr[i] == bgp_data['dest_ip']:
#                #srx_data = {'spine_loopback': bgp_data['source_ip'], 'srx_loopback': bgp_data['dest_ip'], 'peer_as' : bgp_data['source_asn'], 'local_as' : bgp_data['dest_asn']}
#                    srx_data = {'source_ip': bgp_data['source_ip'], 'dest_ip': bgp_data['dest_ip'], 'source_asn' : #bgp_data['source_asn'], 'dest_asn' : bgp_data['dest_asn']}
#                    spine_srx_data.append(srx_data)
#            bgp_config=render_bgp_protocol(spine_srx_data)
#            #render routing instance and policy options (rtg inst) config and combine the two
#            srx_config=render_rtginst_policyop(bp_nodes)
#            
#    return bgp_config

def render_bgp_protocol(spine_srx_data):
    #create protocols template from protocols jinja
    protocol = Environment(loader=FileSystemLoader(THIS_DIR),
                  trim_blocks=True, lstrip_blocks=True)

    bgp_config = protocol.get_template('protocols.j2').render(
                     srx_bgp = spine_srx_data
    )
    return bgp_config

def render_rtginst_policyop(bp_nodes,srx_ip):
    for node in bp_nodes:
        if node[2] == 'leaf':
            leaf_node_found = True
            break
    device_context = get_device_context(aos_url,token,bp_id,node[0])
    context=[]
    context=json.loads(device_context['context'])
    rt_instances= context['security_zones']
    protocol = Environment(loader=FileSystemLoader(THIS_DIR),
                  trim_blocks=True, lstrip_blocks=True)
    rt_inst_config = protocol.get_template('routing_instances.j2').render(
            local_addr = srx_ip, rt_instances = rt_instances
        )
    policy_op_config = protocol.get_template('policy-options.j2').render(
            rt_instances = rt_instances
        )
    rtinst_policy_config = rt_inst_config + '\n' + policy_op_config
    return rtinst_policy_config

def write_srx_file(srx_ip,bgp_config,srx_config):
    #Now write file for base_srx_config
    #for i in range(len(srx_lpbck_addr)):
    if os.path.isfile("base_srx_config_" + srx_ip + ".txt"):
        os.remove("base_srx_config_" + srx_ip + ".txt")
        #srx_filenm = open("base_srx_config_" + srx_ip + ".txt","a")
    else:
        print ("* * * Adding protocols bgp, routing-inst and Policy options to base_srx_config_"+ srx_lpbck_addr[i]+ ".txt * * *\n")
        srx_filenm = open("base_srx_config_" + srx_ip + ".txt","w")
        try:
            srx_filenm.write(bgp_config)
            srx_filenm.write('\n')
            srx_filenm.write(srx_config)
            srx_filenm.write('\n')
        except Exception as e:
            sys.exit("File " + "base_srx_config_" + srx_lpbck_addr[i] + ".txt write error. In case if file is open then close file.")

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
    
    # Aos url
    if aos_port != "":
        aos_url = "https://"+ aos_ip + ":" + str(aos_port)
    else:
        aos_url = "https://"+ aos_ip
        
    
    if aos_user == "":
        aos_user = "admin"
    # Next get auth token by logging into Apstra
    token = apstra_auth_token(aos_url, aos_user, aos_password)
    # Get all blueprint list and inquire with user to get input
    blueprintlist=get_blueprints(aos_url, token)
    #print("Blueprint list ",blueprintlist )
        
    #while True:
    #    aos_blueprint = input("Enter Blueprint Name as shown in Apstra: ")
    questions = [
      inquirer.List('Blueprint Names',
                    message="Select the blueprint that is configured for Connected-Security",
                    choices=[blueprintlist[i]['label'] for i in range(len(blueprintlist))],
                ),
    ]
    answers = inquirer.prompt(questions)
    #print ("Answer is ", answers)
    print ("* * * Blueprint Selected is " + answers['Blueprint Names'] +"* * *\n")
    bpid = [b['id'] for b in blueprintlist if b['label'] == answers['Blueprint Names']]
    #print ("Selected Blueprint ID is ", bpid)
    aos_blueprint = answers['Blueprint Names']
    # Next get get blueprint ID
    #bp_id = get_user_blueprint_id()
    bp_id = ""
    if bpid:
        bp_id = bpid[0]
    else:
        sys.exit("Blueprint ID not found. Exiting..")
    print ("* * * Blueprint found. Now getting Blueprint Nodes... * * *\n")
    # Next get leaf and spine nodes from Blueprint
    bp_nodes = get_bp_nodes(aos_url, token,bp_id)
    print ("* * * Blueprint Nodes found. Now checking for SRX configured on Blueprint... * * *\n")
    #print ('Nodes are ', bp_nodes)
    node_id=''
    
    srx_bgp = []
    srx_bgp_session = []
    srx_lpbck_addr = []
    leaf_node_found = False

    #write config generated below to srx config file
    THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    fileList = glob.glob('base_srx_config_*.txt')
    if fileList != []:
        for filePath in fileList:
            try:
                os.remove(filePath)
            except:
                pass
    srx_count = 0
    spine_node = []
    spine_srx_bgp = []
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

        #Check if SRXs are connected
        if srx_count == 0:
            sys.exit("No SRXs were connected to this Blueprint. Exiting..")
        else:
            print ("* * * SRX is connected to the Spines on Blueprint. Generating SRX config files... * * *\n")
            
        #print ('srx_lpbck_addr before ', srx_lpbck_addr)
        [srx_lpbck_addr.append(item['dest_ip']) for item in srx_bgp if item['dest_ip'] not in srx_lpbck_addr]
        #print ('srx_lpbck_addr are ', srx_lpbck_addr)
        #print ('srx_bgp is', srx_bgp)

        #Build config for each srx towards each spine, first sort and render bgp config and routing inst
        spine_srx_data = []
        if srx_bgp != [] :
            for i in range(len(srx_lpbck_addr)):
                spine_srx_data = []
                for bgp_data in srx_bgp:
                    if srx_lpbck_addr[i] == bgp_data['dest_ip']:
                        # Could have reversed this but this works as the SRX BGP config is built
                    #srx_data = {'spine_loopback': bgp_data['source_ip'], 'srx_loopback': bgp_data['dest_ip'], 'peer_as' : bgp_data['source_asn'], 'local_as' : bgp_data['dest_asn']}
                        srx_data = {'source_ip': bgp_data['source_ip'], 'dest_ip': bgp_data['dest_ip'], 'source_asn' : bgp_data['source_asn'], 'dest_asn' : bgp_data['dest_asn']}
                        spine_srx_data.append(srx_data)
                bgp_config=render_bgp_protocol(spine_srx_data)
                #render routing instance and policy options (rtg inst) config and combine the two
                srx_ip=srx_lpbck_addr[i]
                srx_config=render_rtginst_policyop(bp_nodes,srx_ip)
                write_srx_file(srx_ip,bgp_config,srx_config)

        #Lets check if the file got generated again and print message
        fileList = glob.glob('base_srx_config_*.txt')
        if fileList != []:
           for filePath in fileList:
               print ('* * * SRX config file generated for', filePath)
        else:
            print ('SRX config file not generated at all! Something went wrong..:(')