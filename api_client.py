from jsonrpclib import Server
from pprint import pprint

switch = Server("http://127.0.0.1:48777/command-api")



#switch.runCmds( 1, ["configure", "sampling options", "sampling interval 10", "write"])
'''
switch.runCmds( 1, ["configure", 
                    "telemetry profiles", 
                    "profile EOS_PROFILE",
                    "os eos",
                    "port 6030",
                    "username admin",
                    "password admin",
                    "auth password",
                    "telemetry clients",
                    "group EOS_CLIENTS",
                    "profile EOS_PROFILE",
                    "client 192.168.102.107",
                    "write"])


switch.runCmds( 1, ["configure", 
                    "telemetry profiles", 
                    "profile JUNOS_PROFILE",
                    "os junos",
                    "port 32767",
                    "username admin",
                    "password admin@123",
                    "auth password",
                    "telemetry clients",
                    "group JUNOS_CLIENTS",
                    "profile JUNOS_PROFILE",
                    "client 192.168.102.101",
                    "write"])



switch.runCmds( 1, ["configure", 
                    "telemetry profiles", 
                    "profile IOSXR_PROFILE",
                    "os iosxr",
                    "port 57400",
                    "username clab",
                    "password clab@123",
                    "auth password",
                    "telemetry clients",
                    "group IOSXR_CLIENTS",
                    "profile IOSXR_PROFILE",
                    "client 192.168.102.102",
                    "write"])


switch.runCmds( 1, ["configure", 
                    "router bgp 65001", 
                    "router-id 10.14.88.203",
                    "neighbor 192.168.102.102",
                    "remote-as 65002",
                    "ebgp-multihop 10",
                    "write"])
'''
output = switch.runCmds( 1, ["show sampling internal"])

pprint(output)