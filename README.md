The python script "build_apstra_srx_config.py" is an interactive script that gathers input from user and validates each input. This script can be executed in any python3 environment, preferrably python3.7 and above. It has been tested on MACOS python 3.7 and 3.9
This script will be useful to generate base config for SRX device connected to Fabric. Name of file is of format srx_config_(srx_loopback_ip).txt

Pre-requisite:
1. Ensure you have fabric provisioned on Apstra and is connected SRX.
2. Note that the script requires valid Apstra IP, port (if different to 443), username (if different to admin), password and blueprint name where SRX is connected.
3. For now the script will identify SRX connected to spine devices using the Apstra Spine Device-context -> BGPSessions and filtering the sessions based on description as 'srx'. So Ensure the SRX node device is added as generic device with name as srx. (this is expected to change in future if user wants to input the SRX device name as in defined in Apstra)

Example output of the script:
bhaktib@bhaktib-mbp apstra-srx_config % python3 build_apstra_srx_config.py
Enter Apstra IP. Ensure there is connectivity towards Apstra IP: 10.6.1.44
Enter https port if different to 443:
Enter apstra username. if admin then press Enter:
Enter apstra password
Password: *****
Enter Blueprint Name as shown in Apstra: must_blueprint_dc1
Blueprint found.
Blueprint Nodes found
Adding protocols bgp to srx_config_10.99.0.1.txt
Adding protocols lldp, routing_instances, policy_options to srx_config_10.99.0.1.txt
SRX config file generated for srx_config_10.99.0.1.txt
