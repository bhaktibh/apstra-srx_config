# About build_apstra_srx_config.py
The python script "build_apstra_srx_config.py" is an interactive script that gathers input from user and validates each input. This script can be executed in any python3 environment, preferrably python3.7 and above. It has been tested on MACOS python 3.7 and 3.9
This script will be useful to generate SRX base config (using the jinja2 files provided with this repository) which is connected to Spine Devices . Name of file is of format srx_config_(srx_loopback_ip).txt

## Installing pyton modules
After cloning this report, from the same directory run **pip3 install -r requirements.txt**

## Pre-requisite:
1. Ensure you have fabric provisioned on Apstra and is connected SRX. **Note: The SRX should be connected to the Spine devices as per the design, contact Ben Griffin for more information on the Network Design**
2. Note that the script requires valid Apstra IP, port (if different to 443), username (if different to admin), password and blueprint name where SRX is connected.
3. For now the script will identify SRX connected to spine devices using the Apstra Spine Device-context -> BGPSessions and filtering the sessions based on description as 'srx'. Ensure that the SRX device is added as generic device with name starting as srx. (this is expected to change in future if user wants to input the SRX device name as in defined in Apstra)

# Execute the Script
**Example output of the script**
*python3 build_apstra_srx_config.py*
1. Enter Apstra IP. Ensure there is connectivity towards Apstra IP: 10.6.1.44
2. Enter https port if different to 443:
3. Enter apstra username. if admin then press Enter:
4. Enter apstra password
5. Password: *****
6. Enter Blueprint Name as shown in Apstra: must_blueprint_dc1
*<After the above input from user the script should proceed to generate the SRX base config>*
7. Blueprint found.
8. Blueprint Nodes found
9. Adding protocols bgp to srx_config_10.99.0.1.txt
10. Adding protocols lldp, routing_instances, policy_options to srx_config_10.99.0.1.txt
11. SRX config file generated for srx_config_10.99.0.1.txt
