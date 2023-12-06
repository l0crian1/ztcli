from tabulate import tabulate
import subprocess
import ipaddress
import json
import re
import os
import requests
from io import StringIO


network_commands = {
  "clear config": {
    "description": "Clear configuration back to default",
    },
  "configure": {
    "description": "Enter Configuration Mode",
    "physical": {
      "description": "Settings that apply to physical L2/L3 network paths",
      "subnet": {
        "AllowedValues": ["IPv4Network"],
        "description": "Network Path to be configured",
        "Config_Path": 'clear.key.physical',
        "expectedoutput": "x.x.x.x/xx",
        "blacklist": {
          "AllowedValues": ["specific"],
          "description": "Defines whether ZeroTier traffic can function over the Network Path",
          "Config_Path": 'physical.{{last_value}}.blacklist',
          "expectedoutput": "true|false"
        },
        "mtu": {
          "AllowedValues": ["integer"],
          "description": "Defines the Maximum Transmission Unit over the Network Path",
          "Config_Path": 'physical.{{last_value}}.mtu',
          "expectedoutput": "500-1500"
        },
        "trustedPathId": {
          "AllowedValues": ["integer"],
          "description": "Defines the Trusted Path ID of the network path (WARNING: disables authentication and encryption)",
          "Config_Path": 'physical.{{last_value}}.trustedPathId',
          "expectedoutput": "0-100000"
        }
      }
    },
    "virtual": {
      "description": "Settings applied to ZeroTier virtual network devices (VL1)",
      "vl1": {
        "AllowedValues": ["tendhex"],
        "expectedoutput": "10-digit value",
        "Config_Path": 'clear.key.virtual',
        "description": "Settings applied to ZeroTier virtual network devices (VL1)",
        "blacklist": {
          "AllowedValues": ["IPv4Network"],
          "description": "Blacklist a physical path for only this peer",
          "Config_Path": 'virtual.{{last_value}}.blacklist',
          "expectedoutput": "[x.x.x.x/xx,x.x.x.x/xx]"
        },
        "try": {
          "AllowedValues": ["any"],
          "description": "Hints on where to reach this peer if no upstreams/roots are online",
          "Config_Path": 'virtual.{{last_value}}.try',
          "expectedoutput": "[ip/port,ip/port]"
        }
      }
    },
    "settings": {
      "description": "Other global settings.",
      "allowManagementFrom": {
        "AllowedValues": ["IPv4Network"],
        "description": "If non-NULL, allow JSON/HTTP management from this IP network. Default is 127.0.0.1 only",
        "Config_Path": 'settings.allowManagementFrom',
        "expectedoutput": "[x.x.x.x/xx,x.x.x.x/xx] |null"
      },
      "allowSecondaryPort": {
        "AllowedValues": ["specific"],
        "description": "False will also disable secondary port",
        "Config_Path": 'settings.allowSecondaryPort',
        "expectedoutput": "true|false"
      },
      "allowTcpFallbackRelay": {
        "AllowedValues": ["specific"],
        "description": "Allow or disallow establishment of TCP relay connections (true by default)",
        "Config_Path": 'settings.allowTcpFallbackRelay',
        "expectedoutput": "true|false"
      },
      "bind": {
        "AllowedValues": ["IPv4Address"],
        "description": "If present and non-null, bind to these IPs instead of to each interface (wildcard IP allowed)",
        "Config_Path": 'settings.bind',
        "expectedoutput": "[ \"ip\",... ]"
      },
      "defaultBondingPolicy": {
        "AllowedValues": ["any"],
        "description": "Defines the bonding policy to be applied globally",
        "Config_Path": 'settings.defaultBondingPolicy',
        "expectedoutput": "Policy Name",
      },
      "forceTcpRelay": {
        "AllowedValues": ["specific"],
        "description": "Disables UDP Communication and forces all traffic via a TCP Relay",
        "Config_Path": 'settings.forceTcpRelay',
        "expectedoutput": "true|false"
      },
      "interfacePrefixBlacklist": {
        "AllowedValues": ["any"],
        "description": "Array of interface name prefixes (e.g., eth for eth#) to blacklist for ZT traffic",
        "Config_Path": 'settings.interfacePrefixBlacklist',
        "expectedoutput": "[Interface name(s)]"
      },
      "lowBandwidthMode": {
        "AllowedValues": ["specific"],
        "description": "Enables Low Bandwidth Mode",
        "Config_Path": 'settings.lowBandwidthMode',
        "expectedoutput": "true|false"
      },
      "multipathMode": {
        "AllowedValues": ["specific"],
        "description": "Multipath mode: none (0), random (1), proportional (2)",
        "Config_Path": 'settings.multipathMode',
        "expectedoutput": "0|1|2"
      },
      "peerSpecificBonds": {
        "AllowedValues": ["tendhex"],
        "description": "Applies configured bonding policies per peer",
        "Config_Path": 'clear.key.settings.peerSpecificBonds',
        "expectedoutput": "10-digit VL1 Address",
        "policyname": {
          "AllowedValues": ["any"],
          "description": "Defines a policy to be applied to a specific peer",
          "Config_Path": 'settings.peerSpecificBonds.{{last_value}}',
          "expectedoutput": "VL1 Address"
        },
      },
      "policies": {
        "AllowedValues": ["any"],
        "description": "Configure bonding policies",
        "Config_Path": 'clear.key.settings.policies',
        "expectedoutput": "Name of policy to be configured",
        "basePolicy": {
          "AllowedValues": ["specific"],
          "description": "Defines the type of bonding profile to use",
          "Config_Path": 'settings.policies.{{last_value}}.basePolicy',
          "expectedoutput": "active-backup|broadcast|balance-rr|balance-xor|balance-aware"
        },
        "downDelay": {
          "AllowedValues": ["integer"],
          "description": "How long after a path fails before it is removed from the bond",
          "Config_Path": 'settings.policies.{{last_value}}.downDelay',
          "expectedoutput": "0-65535"
        },
        "failoverInterval": {
          "AllowedValues": ["integer"],
          "description": "How quickly a path on this link should failover after a detected failure",
          "Config_Path": 'settings.policies.{{last_value}}.failoverInterval',
          "expectedoutput": "0-65535"
        },
        "links": {
            "description": "Specify the links that ZeroTier should use in a bonding policy",
            "interface": {
              "description": "Name of an interface to configure policy: ex. 'eth0'",
              "AllowedValues": ["any"],
              "Config_Path": 'key.settings.{{last_value}}.links',
              "expectedoutput": "Interface Name: ex. 'eth0'",
                "ipvPref": {
                  "AllowedValues": ["specific"],
                  "description": "IP version preference for detected paths on a link",
                  "Config_Path": 'settings.policies.{{last_value}}.links.{{last_value}}.ipvPref',
                  "expectedoutput": "0|4|6|46|64"
                },
                "capacity": {
                  "AllowedValues": ["integer"],
                  "description": "How fast this link is (in arbitrary units)",
                  "Config_Path": 'settings.policies.{{last_value}}.links.{{last_value}}.capacity',
                  "expectedoutput": "0-1000000"
                },
                "failoverTo": {
                  "AllowedValues": ["any"],
                  "description": "Which link should be used next after a failure of this link",
                  "Config_Path": 'settings.policies.{{last_value}}.links.{{last_value}}.failoverTo',
                  "expectedoutput": "Interface Name: ex. 'eth0'",
                },
                "mode": {
                  "AllowedValues": ["specific"],
                  "description": "Whether this link is used by default or only after failover events",
                  "Config_Path": 'settings.policies.{{last_value}}.links.{{last_value}}.mode',
                  "expectedoutput": "primary|spare"
                }
            },
        },
        "linkSelectMethod": {
          "AllowedValues": ["specific"],
          "description": "Specifies the selection policy for the active link during failure and/or recovery events",
          "Config_Path": 'settings.policies.{{last_value}}.linkSelectMethod',
          "expectedoutput": "always|better|optimize|failure"
        },
        "linkQuality": {
          "description": "Provide hints to ZeroTier as to when a link is no longer suitable for use",
          "lat_max": {                
            "AllowedValues": ["float"],
            "description": "Maximum (mean) latency observed over many samples",
            "Config_Path": 'settings.policies.{{last_value}}.linkQuality.lat_max',
            "expectedoutput": "Float Number: e.g. 1.0"
            },
          "pdv_max": {
            "AllowedValues": ["float"],
            "description": "Maximum packet delay variance (similar to jitter)",
            "Config_Path": 'settings.policies.{{last_value}}.linkQuality.pdv_max',
            "expectedoutput": "Float Number: e.g. 1.0"
            },
          "lat_weight": {
            "AllowedValues": ["float"],
            "description": "Define the level of importance of latency",
            "Config_Path": 'settings.policies.{{last_value}}.linkQuality.lat_weight',
            "expectedoutput": "Decimal (lat and pdv weight must equal 1): ex. '.5'"
            } ,
          "pdv_weight": {
            "AllowedValues": ["float"],
            "description": "Define the level of importance of packet delay variance",
            "Config_Path": 'settings.policies.{{last_value}}.linkQuality.pdv_weight',
            "expectedoutput": "Decimal (lat and pdv weight must equal 1): ex. '.5'"
            }
        },
        "upDelay": {
          "AllowedValues": ["integer"],
          "description": "How long after a path becomes alive before it is added to the bond",
          "Config_Path": 'settings.policies.{{last_value}}.upDelay',
          "expectedoutput": "0-65535"
        },
      },
      "portMappingEnabled": {
        "AllowedValues": ["specific"],
        "description": "If true (the default), try to use uPnP or NAT-PMP to map ports",
        "Config_Path": 'settings.portMappingEnabled',
        "expectedoutput": "true|false"
      },
      "primaryPort": {
        "AllowedValues": ["integer"],
        "description": "If set, override default port of 9993 and any command line port",
        "Config_Path": 'settings.primaryPort',
        "expectedoutput": "1-65535"
      },
      "secondaryPort": {
        "AllowedValues": ["integer"],
        "description": "If set, override default random secondary port",
        "Config_Path": 'settings.secondaryPort',
        "expectedoutput": "1-65535"
      },
      "softwareUpdate": {
        "AllowedValues": ["specific"],
        "description": "Automatically apply updates, just download, or disable built-in software updates",
        "Config_Path": 'settings.softwareUpdate',
        "expectedoutput": "apply|download|disable"
      },
      "softwareUpdateChannel": {
        "AllowedValues": ["specific"],
        "description": "Software update channel",
        "Config_Path": 'settings.softwareUpdateChannel',
        "expectedoutput": "release|beta"
      },
      "softwareUpdateDist": {
        "AllowedValues": ["specific"],
        "description": "If true, distribute software updates (only really useful to ZeroTier, Inc. itself, default is false)",
        "Config_Path": 'settings.softwareUpdateDist',
        "expectedoutput": "true|false"
      },
      "tcpFallbackRelay": {
        "AllowedValues": ["any"],
        "description": "Defines the IP and Port of a remote TCP Relay",
        "Config_Path": 'settings.tcpFallbackRelay',
        "expectedoutput": "IPv4 Address/Port"
      },
      "tertiaryPort": {
        "AllowedValues": ["integer"],
        "description": "If set, override default random tertiary port",
        "Config_Path": 'settings.tertiaryPort',
        "expectedoutput": "1-65535"
      }
    }
  },
  "exit": {
    "description": "Go back one level; exits script if at top level"
    },
  "restart": {
    "description": "Restart the zerotier-one service",
    "command": "/etc/init.d/zerotier-one restart"
  },
  "save": {
    "description": "Save the configuration to disk"
    },
  "set": {
      "description": "Set allowManaged, allowGlobal, allowDefault, and allowDNS settings",
      "allowManaged": {
        "description": "Allow Routes to be pushed from ZeroTier Central",
        "command": "zerotier-cli set {{user_input}} allowManaged={{set_command}}",
        "enable": "",
        "disable": "",
        "prompt": "Enter a Network ID: "
      },
      "allowGlobal": {
        "description": "Allow Routes to be in Public IP space",
        "command": "zerotier-cli set {{user_input}} allowGlobal={{set_command}}",
        "enable": "",
        "disable": "",
        "prompt": "Enter a Network ID: "
      },
      "allowDefault": {
        "description": "Allow a default route to be pushed from ZeroTier Central",
        "command": "zerotier-cli set {{user_input}} allowDefault={{set_command}}",
        "enable": "",
        "disable": "",
        "prompt": "Enter a Network ID: "
      },
      "allowDNS": {
        "description": "Allow ZeroTier DNS",
        "command": "zerotier-cli set {{user_input}} allowDNS={{set_command}}",
        "enable": "",
        "disable": "",
        "prompt": "Enter a Network ID: "
      }    
  },
  "show": {
    "description": "Show ZeroTier information",
    "config": {
      "description": "Show the current running config",
    },
    "controller": {
      "description": "Show information from Zerotier Central's API",
      "network": {          
        "description": "List all networks in ZeroTier Central account",
        "networkID": {
          "description": "Specify a network within ZeroTier Central",
          "expectedoutput": "Valid Network ID in ZeroTier Central",
          "member": {
            "description": "List all networks in ZeroTier Central account",
            "memberID": {
              "description": "Specify a Node in ZeroTier Central",
              "expectedoutput": "Valid Node ID in ZeroTier Central"
            }
          }
        }
      },
      "status": {          
        "description": "Obtain the overall status of the account tied to ZeroTier Central",
        "command": "zerotier-cli bond list"
      }
    },
    "info": {
      "description": "Show information for local Node",
      "command": "zerotier-cli info"
    },
    "metrics": {
      "description": "Show Metric information",
      "acceptedpackets": {          
        "description": "Show allowed/blocked metrics",
      },
      "errors": {          
        "description": "Show error metrics",
      },
      "latency": {          
        "description": "Show per node latency numbers by packet",
      },
      "peerpackets": {          
        "description": "Show Peer Packet Cout",
      },
      "packettype": {          
        "description": "Show Packet Type",
      },
      "protocols": {          
        "description": "Show counts per protocol",
      }
    },
    "peers": {
      "description": "List all peers",
      "command": "zerotier-cli listpeers",
      "detail": {          
        "description": "Detailed view of Active Peers"
        }
    },
    "networks": {
      "description": "List all networks",
      "command": "zerotier-cli listnetworks"
    },
    "bond": {
      "description": "Show ZeroTier Bonding information",
      "list": {          
        "description": "List all nodes using bonding",
        "command": "zerotier-cli bond list"
      },
      "node": {
        "description": "Show detailed output of specific Node's bonding",      
        "command": "zerotier-cli bond {{user_input}} show",
        "prompt": "Enter a 10-digit node ID: "
      }
    }
  },
  "top": {      
     "description": "Go to beggining of all hierarchies",
     }
}

default_structure = {
    "physical": {},
    "virtual": {},
    "settings": {}
}

def save(local_config, file):
    with open('local.conf', 'w') as file:
        json.dump(local_config, file, indent=4)
    print(f"Configuration saved to local.conf.")
    

if os.path.exists('local.conf'):
    with open('local.conf', 'r') as file:
        local_config = json.load(file)
        for key in default_structure:
            if key not in local_config:
                local_config[key] = default_structure[key]
else:
    local_config = default_structure.copy()
    save(local_config, 'local.conf')


def create_eval_string(base, inputs):
    for key in inputs:
        base += f"[\"{key}\"]"
    return base


def create_table(data_dict, headers):
    table_data = []
    for key, value in data_dict.items():
        if key not in ['description', 'expectedoutput']:
            row = [key]
            if 'description' in headers:
                row.append(value.get('description', ''))
            if 'expectedoutput' in headers:
                row.append(value.get('expectedoutput', ''))
            table_data.append(row)
    return table_data


def build_table_data(current_level, excluded_keys):
    table_data = []
    headers = ['Command']

    for details in current_level.values():
        if isinstance(details, dict):
            if 'description' in details and 'Description' not in headers:
                headers.append('Description')
            if 'expectedoutput' in details and 'Expected Output' not in headers:
                headers.append('Expected Output')

    for command, details in current_level.items():
        if command in excluded_keys:
            continue
        row = [command]
        if isinstance(details, dict):
            if 'description' in details:
                row.append(details.get('description', ''))
            if 'expectedoutput' in details:
                row.append(details.get('expectedoutput', ''))
        table_data.append(row)
    
    return headers, table_data


def print_table(headers, table_data):
    print(tabulate(table_data, headers=headers, tablefmt='github'))
    
    
def validate_input_value(command, value, expectedoutput, current_level):
    allowed_values = current_level['AllowedValues']

    def is_valid_ipv4_network(network):
        import ipaddress
        try:
            net = ipaddress.ip_network(network, strict=False)
            if '/' in network and str(net.network_address) == network.split('/')[0]:
                return True
        except ValueError:
            print('fail')
            return False
        return False

    def is_valid_ipv4_address(ip):
        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
            return addr.version == 4
        except ValueError:
            return False

    if 'integer' in allowed_values:
        try:
            int(value)
            return True
        except ValueError:
            return False
    if 'float' in allowed_values:
        if isinstance(float(value), float):
            return True
        else:
            return False 
    elif 'any' in allowed_values:
        networks = value.split(',')
        return True 
    elif 'IPv4Network' in allowed_values:
        networks = value.split(',')
        return all(is_valid_ipv4_network(network.strip()) for network in networks)    
    elif 'IPv4Address' in allowed_values:
        ips = value.split(',')
        return all(is_valid_ipv4_address(ip.strip()) for ip in ips)
    elif 'tendhex' in allowed_values:
        return bool(re.match(r"^[A-Fa-f0-9]{10}$", value))
    elif 'specific' in allowed_values:
        return value.lower() in expectedoutput.split('|')

    return value in allowed_values


def infer_type(value, allowedvalues):
    if 'float' in allowedvalues:
        try:
            return float(value)
        except:
            pass
    elif 'integer' in allowedvalues:
        try:
            return int(value)
        except ValueError:
            pass
    elif 'specific' in allowedvalues:    
        try:
            return int(value)
        except ValueError:
            pass
        if value.lower() in ('true', 'false'):
            return value.lower() == 'true'

    return value


def add_to_nested_dict(d, keys, value, cl):
    current_level = d
    for key in keys[:-1]:
        if key not in current_level:
            current_level[key] = {}
        current_level = current_level[key]

    current_level[keys[-1]] = infer_type(value, cl['AllowedValues'])

    
def check_for_diff(file_path, local_config):
    with open(file_path, 'r') as file:
        file_config = json.load(file)
    
    if file_config != local_config:        
        print("Running Config not synced; run the save command to sync")
        

def get_user_input():
    global dictString
    if 'configure' in dictString:
        promptIcon = '#'
    else:
        promptIcon = '->'
    cliPromptText = '-'.join(dictString.split('][')).replace('network_commands','').replace('[','').replace(']','').replace("\"","")
    userInput = input(f"ZeroTier{'-' if cliPromptText else ''}{cliPromptText}{promptIcon} ").strip().replace('ZeroTier->','').split()

    return userInput


def context_help(userInput):
    global dictString
    userInput.pop()
    try:
        eval(create_eval_string(dictString, userInput))
        temp_level = eval(create_eval_string(dictString, userInput))
        headers, table_data = build_table_data(temp_level, excluded_keys)
        print_table(headers, table_data)        
    except:
        print("invalid entry")

        
def show():
    userValue = ""
    if 'config' in userInput:
        check_for_diff('local.conf', local_config)
        print(json.dumps(local_config, indent=4))
        return 
    try:
        showJSON = ""
        if '-j' in userInput or 'json' in userInput:
            userInput.pop()
            showJSON = " -j"
        eval(create_eval_string(dictString, userInput))
        temp_level = create_eval_string(dictString, userInput)
        if '{{user_input}}' in eval(temp_level)['command']:
            userValue = input(eval(temp_level)['prompt'])
        if 'command' in temp_level:
            result = subprocess.check_output(eval(temp_level)['command'].replace("{{user_input}}", userValue)+showJSON, shell=True, stderr=subprocess.STDOUT)
            print(result.decode("utf-8"))              
    except:
        print("invalid entry")
        

def clear_config(config):
    if 'config' in userInput:
        while True:
            userVerification = input("Are you sure you want to clear the running configuration?(yes/no): ")
            if userVerification.lower() == 'yes':
                config = default_structure
                print(config)
                return config
            elif userVerification.lower() == 'no':
                return config
            else:
                print("Invalid Entry, please type 'yes' or 'no'")
                
def apply_allow_settings():
    if userInput[-1] == 'disable':
        enable_disable = '0'
        userInput.pop()
    elif userInput[-1] == 'enable':
        enable_disable = '1'
        userInput.pop()
        
    try:
        eval(create_eval_string(dictString, userInput))
        temp_level = create_eval_string(dictString, userInput)
        if '{{user_input}}' in eval(temp_level)['command']:
            userValue = input(eval(temp_level)['prompt'])
            
        setCommand = eval(temp_level)['command'].replace('{{user_input}}', userValue).replace('{{set_command}}', enable_disable)
    
        if 'command' in temp_level:
            result = subprocess.check_output(setCommand, shell=True, stderr=subprocess.STDOUT)
            print(result.decode("utf-8"))              
    except:
        print("invalid entry")
    #{{set_command}}

def show_controller():
    global dictString, userInput
    
    try:
        with open('zt_central_api.secret', 'r') as file:
            token = file.read()
    except FileNotFoundError:
        token = input("ZeroTier API Secret file not found, please enter the ZeroTier Central API Key: ")
        with open('zt_central_api.secret', 'w') as file:
            file.write(token)
            print(f"File zt_central_api.secret created with token: {token}")
            
    if len(userInput) > 2:        
        if '?' in userInput:
            try:                
                userInput[3] = 'networkID'
                userInput[5] = 'memberID'
            except:
                pass
        
            context_help(userInput)
        else:
            apiString = '/'.join(userInput).replace('show/controller/','')

            url = f'https://api.zerotier.com/api/v1/{apiString}'

            headers = {
                'Authorization': f'token {token}'
            }

            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                network_data = response.json()
                print(json.dumps(network_data, indent=2))
            else:
                print(f'Error Code: {response.status_code}')      
        
def show_peer_details():
    global response

    tableHeaders = ['Name', 'NodeID', 'Description', 'ZeroTier IP', 'Network', 'Version']
    try:
        with open('zt_central_api.secret', 'r') as file:
            api_token = file.read()
    except FileNotFoundError:
        api_token = input("ZeroTier API Secret file not found, please enter the ZeroTier Central API Key: ")
        with open('zt_central_api.secret', 'w') as file:
            file.write(api_token)
            print(f"File zt_central_api.secret created with token: {api_token}")
            
    try:
        with open('authtoken.secret', 'r') as file:
            authtoken = file.read()
    except FileNotFoundError:
        print('authtoken.secret not found! This should have been created when installing ZeroTier')

    localNodeList = []
    controllerNodeList = []
    controllerNetworkList = []

    def zt_central_api(url):
        headers = {
            'Authorization': f'token {api_token}'
        }

        return requests.get(url, headers=headers)
    
    def zt_service_api():
        url = f'http://127.0.0.1:9993/peer'

        headers = {
            "X-ZT1-Auth": authtoken
        }

        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            network_data = response.json()
            for peers in network_data:
                localNodeList.append(peers['address'])
        else:
            print(f'Error Code: {response.status_code}')
            
    zt_service_api()
    response = zt_central_api('https://api.zerotier.com/api/v1/network')
    if response.status_code == 200:
        network_data = response.json()
        for networks in network_data:
            controllerNetworkList.append(networks['id'])
    else:
        print(f'Error Code: {response.status_code}')

    for controllerNode in controllerNetworkList:
        response = zt_central_api(f'https://api.zerotier.com/api/v1/network/{controllerNode}/member')
        network_data = response.json()
        for i in network_data:
            if i['nodeId'] in localNodeList:
                controllerNodeList.append([i['name'], i['nodeId'], i['description'], i['config']['ipAssignments'], i['networkId'], i['clientVersion']])
    print_table(tableHeaders, controllerNodeList)

def show_metrics():
    accepted_packets_list = []
    errors_list =  []
    latency_list = []
    peer_packet_list = []
    packet_type_list = []
    protocol_list = []
    try:
        with open('metricstoken.secret', 'r') as file:
            authtoken = file.read()
    except FileNotFoundError:
        print('authtoken.secret not found! This should have been created when installing ZeroTier')
        
    url = f'http://127.0.0.1:9993/metrics'

    headers = {
        "X-ZT1-Auth": authtoken
    }

    response = requests.get(url, headers=headers)
    #print(response)
    if response.status_code == 200:
        network_data = response
    else:
        print(f'Error Code: {response.status_code}')
    #print(network_data.text)
    for i in network_data.text.split('\n'):
        if 'packettype' in userInput:
            if 'packet_type=' in i:
                packet_type_list.append(i.replace('zt_packet{','').replace('"} ', '",').replace('direction="tx"', 'tx').replace('direction="rx"', 'rx').replace('packet_type="', '').replace('"', '').split(','))
        elif 'errors' in userInput:
            if 'error_type=' in i:
                errors_list.append(i.replace('zt_packet_error{','').replace('"} ', '",').replace('direction="tx"', 'tx').replace('direction="rx"', 'rx').replace('error_type="', '').replace('"', '').split(','))            
        elif 'acceptedpackets' in userInput:
            if 'zt_network_packets{' in i:
                accepted_packets_list.append(i.replace('zt_network_packets{','').replace('"', '').replace('accepted=', '').replace('direction=', '').replace('network_id=', '').replace('} ', ',').split(','))
        elif 'protocols' in userInput:
            if 'protocol="' in i:
                protocol_list.append(i.replace('zt_data{','').replace('"', '').replace('protocol=', '').replace('direction=', '').replace('} ', ',').split(','))
        elif 'peerpackets' in userInput:
            if 'zt_peer_packets{' in i:
                peer_packet_list.append(i.replace('zt_peer_packets{','').replace('"', '').replace('direction=', '').replace('node_id=', '').replace('} ', ',').split(','))
        elif 'latency' in userInput:
            if 'zt_peer_latency_bucket{' in i:
                latency_list.append(i.replace('zt_peer_latency_bucket{','').replace('"', '').replace('node_id=', '').replace('} ', ',').split(','))
    if 'peerpackets' in userInput:
        # Initialize a dictionary to store aggregated counts
        aggregated_counts = {}

        # Process and aggregate the data
        for direction, peer_pack, count in peer_packet_list:
            count = int(count)

            if peer_pack not in aggregated_counts:
                aggregated_counts[peer_pack] = {'rx': 0, 'tx': 0}
            
            aggregated_counts[peer_pack][direction] += count

        # Convert the aggregated data to a list of lists for tabulate

        sorted_list = sorted([[peer_pack, counts['rx'], counts['tx']] for peer_pack, counts in aggregated_counts.items()], key=lambda x: x[0])
        # Print the formatted data using tabulate
        print(tabulate(sorted_list, headers=["Protocol", "RX Count", "TX Count"], tablefmt="github"))
    elif 'protocols' in userInput:
        # Initialize a dictionary to store aggregated counts
        aggregated_counts = {}

        # Process and aggregate the data
        for direction, proto_type, count in protocol_list:
            count = int(count)

            if proto_type not in aggregated_counts:
                aggregated_counts[proto_type] = {'rx': 0, 'tx': 0}
            
            aggregated_counts[proto_type][direction] += count

        # Convert the aggregated data to a list of lists for tabulate

        sorted_list = sorted([[proto_type, counts['rx'], counts['tx']] for proto_type, counts in aggregated_counts.items()], key=lambda x: x[0])
        # Print the formatted data using tabulate
        print(tabulate(sorted_list, headers=["Protocol", "RX Count", "TX Count"], tablefmt="github"))
    elif 'packettype' in userInput:
        # Initialize a dictionary to store aggregated counts
        aggregated_counts = {}

        # Process and aggregate the data
        for direction, packet_type, count in packet_type_list:
            count = int(count)

            if packet_type not in aggregated_counts:
                aggregated_counts[packet_type] = {'rx': 0, 'tx': 0}
            
            aggregated_counts[packet_type][direction] += count

        # Convert the aggregated data to a list of lists for tabulate

        sorted_list = sorted([[error_type, counts['rx'], counts['tx']] for error_type, counts in aggregated_counts.items()], key=lambda x: x[0])
        # Print the formatted data using tabulate
        print(tabulate(sorted_list, headers=["Packet Type", "RX Count", "TX Count"], tablefmt="github"))
    elif 'errors' in userInput:
        # Initialize a dictionary to store aggregated counts
        aggregated_counts = {}

        # Process and aggregate the data
        for direction, error_type, count in errors_list:
            count = int(count)

            if error_type not in aggregated_counts:
                aggregated_counts[error_type] = {'rx': 0, 'tx': 0}
            
            aggregated_counts[error_type][direction] += count

        # Convert the aggregated data to a list of lists for tabulate
        sorted_list = sorted([[error_type, counts['rx'], counts['tx']] for error_type, counts in aggregated_counts.items()], key=lambda x: x[0])
        print(tabulate(sorted_list, headers=["Error Type", "RX Count", "TX Count"], tablefmt="github"))
    elif 'acceptedpackets' in userInput:
        sorted_list = sorted(accepted_packets_list, key=lambda x: (x[2], x[0]))

        print(tabulate(sorted_list, headers=["Allowed", "Direction", "NetworkID", "Count"], tablefmt="github"))
    elif 'latency' in userInput:
        # Initialize a dictionary to store the data
        # Initialize a dictionary to store the data
        node_data = {}

        # Process the data to merge values
        for node_id, le_value, count in latency_list:
            if node_id not in node_data:
                node_data[node_id] = {}
            node_data[node_id][le_value] = int(count)

        # Headers for the table
        headers = ["NodeID", "le=1", "le=3", "le=6", "le=10", "le=30", "le=60", "le=100", "le=300", "le=600", "le=1000", "le=+Inf"]

        # Convert the processed data to a list for printing
        table_data = []

        for node_id, counts in sorted(node_data.items()):
            row = [node_id] + [counts.get(le, 0) for le in headers[1:]]
            table_data.append(row)

        sorted_list = sorted(table_data, key=lambda x: (x[2], x[0]))

        print(tabulate(sorted_list, headers=["NodeID", "le=1", "le=3", "le=6", "le=10", "le=30", "le=60", "le=100", "le=300", "le=600", "le=1000", "le=+Inf", ], tablefmt="github"))


dictString = "network_commands"
current_level = eval(dictString)
last_value = []
    
def cli():
    global dictString, current_level, last_value, local_config, userInput, excluded_keys    
    excluded_keys = {'description', 'AllowedValues', 'Config_Path', 'expectedoutput', 'command', 'prompt', 'apiCall'}
    while True:
        
        userInput = get_user_input()
        if 'show controller' in ' '.join(userInput) or 'show controller' in ''.join(dictString):
            show_controller()
        elif '?' in userInput:
            context_help(userInput)
        elif 'show metrics' in ' '.join(userInput):
            show_metrics()
        elif not userInput:
            continue
        elif 'show peers detail' in ' '.join(userInput):
            show_peer_details()
            continue
        elif 'show' in userInput or 'restart' in userInput:
            if show():
                continue
        elif 'exit' in userInput:
            if '[' in dictString:
                dictString = dictString[:dictString.rfind('[')]
            else:
                break
        elif 'top' in userInput:
            dictString = "network_commands"
        elif 'save' in userInput:
            save(local_config, 'local.conf')
        elif 'clear config' in ' '.join(userInput):
            local_config = clear_config(local_config)
        elif userInput[0] == 'set':
            apply_allow_settings()
        else:
            try:
                eval(create_eval_string(dictString, userInput))
                dictString = create_eval_string(dictString, userInput)
                current_level = eval(dictString)
                if 'expectedoutput' in current_level and 'Config_Path' in current_level:
                    currentCommand = userInput[-1:][0]
                    while True:
                        configInput = input(f"Enter value for {currentCommand} (Example: {current_level['expectedoutput']}): ")
                        if validate_input_value(currentCommand, configInput, current_level['expectedoutput'], current_level):
                            break
                        else:
                            print(f"Invalid input! Please enter one of the allowed values: {current_level['AllowedValues']}")
                    configPath = current_level['Config_Path'].split('.')
                    if 'key.' in current_level['Config_Path']:
                        if 'clear' in current_level['Config_Path']:
                            last_value.clear()
                        last_value.append(configInput)
                        continue
                    elif '{{last_value}}' in current_level['Config_Path']:
                        valueList = last_value.copy()
                        for i, item in enumerate(configPath):
                            if '{{last_value}}' in item:
                                if valueList:
                                    configPath[i] = item.replace('{{last_value}}', valueList.pop(0), 1)
                                else:
                                    break
                    if ',' in configInput:
                        configInput = configInput.split(',')
                    elif '[' in current_level['expectedoutput'] or ']' in current_level['expectedoutput']:
                        configInput = configInput.split()
                        
                    add_to_nested_dict(local_config, configPath, configInput, current_level)
                    #print(json.dumps(local_config, indent=4))
                    contains_non_excluded_key = any(key not in excluded_keys for key in current_level)
                    if not contains_non_excluded_key:
                        userInput.pop()
                        dictString = dictString.rsplit('"]["', 1)[0] + '"]'
                        current_level = eval(dictString)
                    else:
                        pass
            except Exception as e:
                print(f"An error occurred: {e}")
                #import traceback
                #traceback.print_exc()
                

if __name__ == "__main__":
    cli()
