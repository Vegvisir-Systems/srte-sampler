#!/usr/bin/env python3
from pprint import pprint
import collections.abc
import socket
import copy
from deepdiff import DeepDiff
from eventlet import GreenPool, listen, connect, greenthread, sleep
from eventlet.queue import Queue
from operator import itemgetter
import logging
import json
from time import perf_counter
import ipaddress
import subprocess

class HostnameFormatter(logging.Formatter):
    def format(self, record):
        record.hostname = socket.gethostname()
        return super().format(record)
    
def ip_to_string(ip_address_bin):
    return socket.inet_ntop(socket.AF_INET, ip_address_bin)

def string_to_ip(ip_address_str):
    return socket.inet_pton(socket.AF_INET, ip_address_str)

def ip6_to_string(ip_address_bin):
    return socket.inet_ntop(socket.AF_INET6, ip_address_bin)

def string_to_ip6(ip_address_str):
    return socket.inet_pton(socket.AF_INET6, ip_address_str)


sortable_keys = ["remote_ip", "profile_name", "client_group"]
sortable_keys_by_ip = ["remote_ip"]

def ip_sort_key(d, sort_key):
    ip = d.get(sort_key, '')  # Extract IP address from the dictionary
    try:
        ip_obj = ipaddress.ip_address(ip)
        return (ip_obj.version, ip_obj)
    except ValueError:
        # If not an IP address, return a high value to place it at the end
        return (float('inf'),)

def update_dictionary(d, u, master_arg=None, grandmaster_arg=None):
    for k, v in u.items():
        if isinstance(v, collections.abc.Mapping):
            d[k] = update_dictionary(d.get(k, {}), v, master_arg)
        else:
            if isinstance(v, list):
                updated = False
                if master_arg:
                    for item in d[k]:
                        try:                            
                            if item[master_arg] == v[0][master_arg]:
                                for kk, vv in item.items():
                                    if isinstance(vv, list) and len(v[0][kk]) == 0:
                                        v[0][kk] = vv
                                item.update(v[0])
                                #item = update_dictionary(item, v[0])
                                updated = True
                        except KeyError:
                            if item[grandmaster_arg] == v[0][grandmaster_arg]:
                                #item.update(v[0])
                                item = update_dictionary(item, v[0], master_arg)
                                updated = True
                if not updated:
                    try:
                        # if adding to a list, make sure all elements of the list are sorted
                        # e.g. for proper explicit path indexing, ipv4/ipv6 neighbors etc
                        d[k].append(v[0])
                        if not isinstance(v[0], collections.abc.Mapping):
                            d[k].sort()
                        else: 
                            sort_key = None
                            for item in v[0].keys():
                                if item in sortable_keys:
                                    sort_key = item
                            if sort_key:
                                d[k] = sorted(d[k], key=itemgetter(sort_key))
                                if sort_key in sortable_keys_by_ip:
                                    d[k] = sorted(d[k], key=lambda x: ip_sort_key(x, sort_key))
                                # SR-TE higher path preference is better, so need to reverse the list
                                if sort_key == "path_preference" and isinstance(d[k], list):
                                    d[k].reverse()
                            else:
                                pass
                                #print(f'Unable to sort list {d[k]}')


                    except IndexError:
                        d[k] = copy.deepcopy(v)
            else:
                d[k] = v
    return d


class ConfigCommand:
    def __init__(self, command):
        self.command = command
        self.new_level = None
        self.new_config = None
        self.parent = None
        self.children = []
        self.nested_commands = []
        self.level = None
        self.indent = None
        self.deleter = False
        self.immutable = False
        self.exclusive = False
        self.cli_command = None
        self.cli_level = None
        self.upper_level = "config"
        self.parent_owns_level = False
        self.cli_helpers = []
        self.cli_helper = False
        self.cli_helped_command = None
        self.cli_context_help = "Not available"
        self.cli_allowed_args = "<N/A>"
        self.encrypt = False


    def add_child(self, child):
        child.parent = self
        self.children.append(child)

    def set_level(self, level):
        self.level = level
        level.nested_commands.append(self)

    def add_level(self, level):
        level.nested_commands.append(self)

    def set_result(self, new_level=None, new_config=None):
        self.new_level = new_level
        self.new_config = new_config

    def set_indent(self, indent):
        self.indent = indent

    def set_deleter(self, deleter):
        self.deleter = deleter

    def set_immutable(self):
        self.immutable = True

    def set_exclusive(self):
        self.exclusive = True

    def set_cli_command(self, cli_command):
        self.cli_command = cli_command

    def set_cli_level(self, cli_level):
        self.cli_level = cli_level

    def set_upper_level(self, upper_level):
        self.upper_level = upper_level
    
    def is_cli_helper(self):
        return self.cli_helper
    
    def set_cli_context_help(self, cli_context_help):
        self.cli_context_help = cli_context_help

    def set_cli_allowed_args(self, cli_allowed_args):
        self.cli_allowed_args = cli_allowed_args






class DynamicConfigCommand(ConfigCommand):
    def __init__(self, command):
        super().__init__(command)

    def set_var_ip(self, args):
        pass

    def set_var_ipv4(self, args):
        pass

    def set_var_ipv6(self, args):
        pass

    def set_var_ip_netmask(self, args):
        pass

    def set_var_ipv4_netmask(self, args):
        pass

    def set_var_ipv4_netmask_any(self, args):
        pass

    def set_var_ipv6_netmask(self, args):
        pass

    def set_var_ipv6_netmask_any(self, args):
        pass

    def set_var_iso(self, args):
        pass

    def set_var_iso_ipv4(self, args):
        pass

    def set_var_dec_integer(self, args):
        self.min_value, self.max_value = args

    def set_var_hex_integer(self, args):
        self.min_value = int(args[0], 16)
        self.max_value = int(args[1], 16)

    def set_var_generic_string(self, args):
        self.min_length, self.max_length = args

    def set_var_specific_string(self, args):
        self.possible_values = list(args)

    def set_encrypt(self):
        self.encrypt = True

    SET_VARS = {
        "ip": set_var_ip,
        "ipv4": set_var_ipv4,
        "ipv6": set_var_ipv6,
        "ip_netmask": set_var_ip_netmask,
        "ipv4_netmask": set_var_ipv4_netmask,
        "ipv4_netmask_any": set_var_ipv4_netmask_any,
        "ipv6_netmask": set_var_ipv6_netmask,
        "ipv6_netmask_any": set_var_ipv6_netmask_any,
        "iso": set_var_iso,
        "iso_ipv4": set_var_iso_ipv4,
        "dec_integer": set_var_dec_integer,
        "hex_integer": set_var_hex_integer,
        "generic_string": set_var_generic_string,
        "specific_string": set_var_specific_string
    }

    def check_var_ip(self, command):
        try:
            string_to_ip(command)
        except OSError:
            try:
                command = ip6_to_string(string_to_ip6(command))
            except OSError:
                return False
        return command

    def check_var_ipv4(self, command):
        try:
            string_to_ip(command)
        except OSError:
            return False
        return command

    def check_var_ipv6(self, command):
        try:
            # if configured IPv6 address has unnecessary zeros, remove them
            command = ip6_to_string(string_to_ip6(command))
        except OSError:
            return False
        return command

    def check_var_ip_netmask(self, command):
        if self.check_var_ipv4_netmask(command):
            return command
        return self.check_var_ipv6_netmask(command)

    def check_var_ipv4_netmask(self, command):
        ip_and_mask = command.split("/")
        if len(ip_and_mask) != 2: return False
        ip, mask = ip_and_mask
        try:
            string_to_ip(ip)
        except OSError:
            return False
        try:
            int_mask = int(mask)
            if int_mask < 0: return False
            if int_mask > 32: return False
        except ValueError:
            return False
        return command

    def check_var_ipv4_netmask_any(self, command):
        if command == "any": return command
        return self.check_var_ipv4_netmask(command)

    def check_var_ipv6_netmask(self, command):
        ip_and_mask = command.split("/")
        if len(ip_and_mask) != 2: return False
        ip, mask = ip_and_mask
        try:
            ip = ip6_to_string(string_to_ip6(ip))
        except OSError:
            return False
        try:
            int_mask = int(mask)
            if int_mask < 0: return False
            if int_mask > 128: return False
        except ValueError:
            return False
        command = "/".join([ip, mask])
        return command

    def check_var_ipv6_netmask_any(self, command):
        if command == "any": return command
        return self.check_var_ipv6_netmask(command)
    
    def check_var_iso(self, command):
        # validate that string is an ISO address e.g. 0001.0001.0001
        if type(command) != str:
            return False
        if len(command) != 14:
            return False
        if command[4] != "." or command[9] != ".":
            return False
        split_command = command.split(".")
        for item in split_command:
            try:
                int(item)
            except ValueError:
                return False
        return command
    
    def check_var_iso_ipv4(self, command):
        # check that command is either iso or ipv4
        result = self.check_var_ipv4(command)
        if not result:
            result = self.check_var_iso(command)
        return result

    def check_var_dec_integer(self, command):
        try:
            command = int(command)
        except ValueError:
            return False
        if command > self.max_value or command < self.min_value:
            return False
        return command

    def check_var_hex_integer(self, command):
        try:
            test_command = int(command, 16)
        except ValueError:
            return False
        if test_command > self.max_value or test_command < self.min_value:
            return False
        return command

    def check_var_generic_string(self, command):
        if len(command) > self.max_length or len(command) < self.min_length:
            return False
        return command

    def check_var_specific_string(self, command):
        if command not in self.possible_values:
            return False
        return command
    

    CHECK_VARS = {
        "ip": check_var_ip,
        "ipv4": check_var_ipv4,
        "ipv6": check_var_ipv6,
        "ip_netmask": check_var_ip_netmask,
        "ipv4_netmask": check_var_ipv4_netmask,
        "ipv4_netmask_any": check_var_ipv4_netmask_any,
        "ipv6_netmask": check_var_ipv6_netmask,
        "ipv6_netmask_any": check_var_ipv6_netmask_any,
        "iso": check_var_iso,
        "iso_ipv4": check_var_iso_ipv4,
        "dec_integer": check_var_dec_integer,
        "hex_integer": check_var_hex_integer,
        "generic_string": check_var_generic_string,
        "specific_string": check_var_specific_string
    }


    def set_variable_command(self, var_type, args=None):
        if var_type not in self.SET_VARS.keys():
            print(f'Unknown variable type {var_type}')
            return

        self.var_type = var_type
        func = self.SET_VARS[var_type]
        func(self, args)

    def apply_command(self, command, master_snippet, grandmaster_snippet):
        if isinstance(self.new_config, collections.abc.Sequence):
            args = list(self.new_config)
        else:
            args = [self.new_config]
        command_applied = False
        master_arg = None
        grandmaster_arg = None

        # convert cleartext pwd into hash for /etc/shadow
        if self.encrypt:
            encrypted_command = subprocess.run(
                ["openssl", "passwd", "-6", "-stdin"],
                input=command,
                capture_output=True,
                text=True
            )
            command = encrypted_command.stdout.strip()
        
        if self.var_type not in self.CHECK_VARS.keys():
            #print(f'Incorrect variable type {self.var_type}')
            return None, master_snippet, grandmaster_snippet, master_arg, grandmaster_arg
        

        func = self.CHECK_VARS[self.var_type]
        command = func(self, command)
        if command is False:
            raise ValueError


        while len(args) > 0:
            arg = args.pop(-1)
            if not command_applied:
                if isinstance(arg, DynamicConfigSnippet):
                    if arg.nested and not grandmaster_snippet:                
                        grandmaster_snippet = copy.deepcopy(master_snippet)
                    if not arg.nested:
                        grandmaster_snippet = None
                    if arg.master:
                        config_snippet = {arg.dynamic_arg: command}
                        if arg.embedded_list:
                            if isinstance(arg.embedded_list, tuple):
                                for emb_list in arg.embedded_list:
                                    config_snippet[emb_list] = []
                            else:
                                config_snippet[arg.embedded_list] = []
                        result_config = {arg.dynamic_list_name: [config_snippet]}
                        master_snippet = {arg.dynamic_list_name: [config_snippet]}
                        master_arg = arg.dynamic_arg

                    else:
                        result_config = copy.deepcopy(master_snippet)
                        # exemplary bydlokod
                        try:
                            if command not in result_config[arg.dynamic_list_name][0][arg.dynamic_arg]:
                                result_config[arg.dynamic_list_name][0][arg.dynamic_arg].append(command)
                                # if adding to a list, make sure all elements of the list are sorted
                                # e.g. for proper explicit path indexing, ipv4/ipv6 neighbors etc
                                if not isinstance(command, collections.abc.Mapping):
                                    result_config[arg.dynamic_list_name][0][arg.dynamic_arg].sort()
                                else:
                                    sort_key = None
                                    for item in command.keys():
                                        if item in sortable_keys:
                                            sort_key = item
                                    if sort_key:
                                        result_config[arg.dynamic_list_name][0][arg.dynamic_arg] = sorted(result_config[arg.dynamic_list_name][0][arg.dynamic_arg], key=itemgetter(sort_key))
                                        # SR-TE higher path preference is better, so need to reverse the list
                                        if sort_key in sortable_keys_by_ip:
                                            result_config[arg.dynamic_list_name][0][arg.dynamic_arg] = sorted(result_config[arg.dynamic_list_name][0][arg.dynamic_arg], key=lambda x: ip_sort_key(x, sort_key))
                                        if sort_key == "path_preference" and isinstance(result_config[arg.dynamic_list_name][0][arg.dynamic_arg], list):
                                            result_config[arg.dynamic_list_name][0][arg.dynamic_arg].reverse()
                                    else:
                                        pass
                                        #print(f'Unable to sort list {result_config[arg.dynamic_list_name][0][arg.dynamic_arg]}')
                        except:
                            result_config[arg.dynamic_list_name][0][arg.dynamic_arg] = command
                        master_snippet = copy.deepcopy(result_config)
                        master_arg = arg.master_arg
                else:
                    result_config = copy.deepcopy(master_snippet)
                    if not result_config:
                        result_config = {arg: command}
                    else:
                        result_config[arg] = command
                    master_snippet = copy.deepcopy(result_config)
                command_applied = True                
            else:
                if isinstance(arg, DynamicConfigSnippet):
  
                    grandmaster_snippet[arg.dynamic_list_name][0][arg.dynamic_arg] = (result_config[arg.dynamic_arg])
                    result_config = grandmaster_snippet
                    grandmaster_arg = arg.master_arg
                else:
                    result_config = {arg: result_config}

        return result_config, master_snippet, grandmaster_snippet, master_arg, grandmaster_arg

     
class DynamicConfigSnippet:
    def __init__(self, dynamic_list_name, dynamic_arg, master, master_arg=None, embedded_list=None, nested=False):
        self.dynamic_list_name = dynamic_list_name
        self.dynamic_arg = dynamic_arg
        self.master = master
        self.master_arg = master_arg
        self.embedded_list = embedded_list
        self.nested = nested

class DynamicDeleter:
    def __init__(self, config_path, master_arg, delete_args, grandmaster_arg=None):
        self.config_path = config_path
        self.master_arg = master_arg
        self.delete_args = delete_args
        self.grandmaster_arg = grandmaster_arg



# router bgp <asn>
#    router-id <ipv4>
#    !
#    neighbor <ipv4|ipv6>
#       description <name>
#       remote-as <asn>
#       timers <ka> <hold>
#       ebgp-multihop <1-255>
#       shutdown

router = ConfigCommand("router")
router.set_cli_context_help("Routing protocol commands")
router_bgp = ConfigCommand("bgp")
router_bgp.set_cli_context_help("BGP configuration mode")
router_bgp.set_deleter({'bgp': {'asn': None, 'router_id': None, 'neighbors': []}})
router_bgp_asn = DynamicConfigCommand("asn")
router_bgp_asn.set_cli_context_help("BGP AS number")
router_bgp_asn.set_cli_allowed_args("<1-4294967295>")
router.add_child(router_bgp)
router_bgp.add_child(router_bgp_asn)
router_bgp_asn.set_variable_command(var_type="dec_integer", args=(1, 4294967295))
router_bgp_asn.set_result(new_level=router_bgp_asn, new_config=("bgp", "asn"))
router_bgp_asn.set_immutable()
#router_bgp_asn.set_cli_command("router bgp")
router_bgp_asn.set_cli_level("config-router-bgp")

router_bgp__router_id = ConfigCommand("router-id")
router_bgp__router_id.set_cli_context_help("BGP router identifier")
router_bgp__router_id.set_deleter({'bgp': {'router_id': None}})
router_bgp__router_id.set_level(router_bgp_asn)
router_bgp__router_id_value = DynamicConfigCommand("router_id")
router_bgp__router_id_value.set_variable_command(var_type="ipv4", args=None)
router_bgp__router_id_value.set_result(new_config=("bgp", "router_id"))
router_bgp__router_id_value.set_indent(1)
#router_bgp__router_id_value.set_cli_command("router-id")
router_bgp__router_id.add_child(router_bgp__router_id_value)
router_bgp__router_id_value.set_cli_context_help("BGP router-id value")
router_bgp__router_id_value.set_cli_allowed_args("<ipv4>")

router_bgp__neighbor = ConfigCommand("neighbor")
router_bgp__neighbor.set_cli_context_help("BGP neighbor config mode")
router_bgp__neighbor.set_level(router_bgp_asn)
router_bgp__neighbor.add_level(router_bgp__neighbor)
router_bgp__router_id.add_level(router_bgp__neighbor)

router_bgp__neighbor_value = DynamicConfigCommand("remote_ip")
router_bgp__neighbor_value.set_deleter(True)
router_bgp__neighbor.add_child(router_bgp__neighbor_value)
router_bgp__neighbor_value.set_variable_command(var_type="ip", args=None)
router_bgp__neighbor_value.set_result(new_level=router_bgp__neighbor, new_config=("bgp", DynamicConfigSnippet(dynamic_list_name="neighbors", dynamic_arg="remote_ip", master=True)))
router_bgp__neighbor_value.set_indent(1)
router_bgp__neighbor_value.set_cli_level("config-router-bgp-nbr")
router_bgp__neighbor.set_upper_level(router_bgp_asn)
router_bgp__neighbor_value.parent_owns_level = True
router_bgp__neighbor_value.set_cli_context_help("BGP neighbor IP address")
router_bgp__neighbor_value.set_cli_allowed_args("<ipv4|ipv6>")

router_bgp__neighbor__description = ConfigCommand("description")
router_bgp__neighbor__description.set_level(router_bgp__neighbor)
router_bgp__neighbor__description.set_deleter(DynamicDeleter(config_path=("bgp", "neighbors"), master_arg="remote_ip", delete_args="description"))
router_bgp__neighbor__description_value = DynamicConfigCommand("description")
router_bgp__neighbor__description.add_child(router_bgp__neighbor__description_value)
router_bgp__neighbor__description_value.set_variable_command(var_type="generic_string", args=(1, 255))
router_bgp__neighbor__description_value.set_result(new_config=("bgp", DynamicConfigSnippet(dynamic_list_name="neighbors", dynamic_arg="description", master_arg="remote_ip", master=False)))
router_bgp__neighbor__description_value.set_indent(2)
router_bgp__neighbor__description.set_cli_context_help("Description for BGP neighbor")
router_bgp__neighbor__description_value.set_cli_context_help("Description for BGP neighbor")
router_bgp__neighbor__description_value.set_cli_allowed_args("<TEXT>")


router_bgp__neighbor__remote_as = ConfigCommand("remote-as")
router_bgp__neighbor__remote_as.set_level(router_bgp__neighbor)
router_bgp__neighbor__remote_as.set_deleter(DynamicDeleter(config_path=("bgp", "neighbors"), master_arg="remote_ip", delete_args="remote_as"))
router_bgp__neighbor__remote_as_value = DynamicConfigCommand("remote_as")
router_bgp__neighbor__remote_as.add_child(router_bgp__neighbor__remote_as_value)
router_bgp__neighbor__remote_as_value.set_variable_command(var_type="dec_integer", args=(1, 4294967295))
router_bgp__neighbor__remote_as_value.set_result(new_config=("bgp", DynamicConfigSnippet(dynamic_list_name="neighbors", dynamic_arg="remote_as", master_arg="remote_ip", master=False)))
router_bgp__neighbor__remote_as_value.set_indent(2)
router_bgp__neighbor__remote_as.set_cli_context_help("Remote AS for BGP neighbor")
router_bgp__neighbor__remote_as_value.set_cli_context_help("Remote AS for BGP neighbor")
router_bgp__neighbor__remote_as_value.set_cli_allowed_args("<1-4294967295>")

router_bgp__neighbor__timers = ConfigCommand("timers")
router_bgp__neighbor__timers.set_level(router_bgp__neighbor)
router_bgp__neighbor__timers.set_deleter(DynamicDeleter(config_path=("bgp", "neighbors"), master_arg="remote_ip", delete_args=("keepalive_timer", "hold_timer")))
router_bgp__neighbor__timers_keepalive = DynamicConfigCommand("keepalive_timer")
router_bgp__neighbor__timers.add_child(router_bgp__neighbor__timers_keepalive)
router_bgp__neighbor__timers_keepalive.set_variable_command(var_type="dec_integer", args=(1, 300))
router_bgp__neighbor__timers_keepalive.set_result(new_config=("bgp", DynamicConfigSnippet(dynamic_list_name="neighbors", dynamic_arg="keepalive_timer", master_arg="remote_ip", master=False)))
router_bgp__neighbor__timers_keepalive.set_indent(2)
router_bgp__neighbor__timers_hold = DynamicConfigCommand("hold_timer")
router_bgp__neighbor__timers_keepalive.add_child(router_bgp__neighbor__timers_hold)
router_bgp__neighbor__timers_hold.set_variable_command(var_type="dec_integer", args=(3, 900))
router_bgp__neighbor__timers_hold.set_result(new_config=("bgp", DynamicConfigSnippet(dynamic_list_name="neighbors", dynamic_arg="hold_timer", master_arg="remote_ip", master=False)))
router_bgp__neighbor__timers.set_cli_context_help("Timers for BGP neighbor")
router_bgp__neighbor__timers_keepalive.set_cli_context_help("Keepalive timer for BGP neighbor")
router_bgp__neighbor__timers_keepalive.set_cli_allowed_args("<1-300>")
router_bgp__neighbor__timers_hold.set_cli_context_help("Hold timer for BGP neighbor")
router_bgp__neighbor__timers_hold.set_cli_allowed_args("<3-900>")

router_bgp__neighbor__ebgp_multihop = ConfigCommand("ebgp-multihop")
router_bgp__neighbor__ebgp_multihop.set_level(router_bgp__neighbor)
router_bgp__neighbor__ebgp_multihop.set_deleter(DynamicDeleter(config_path=("bgp", "neighbors"), master_arg="remote_ip", delete_args="ebgp_multihop"))
router_bgp__neighbor__ebgp_multihop_value = DynamicConfigCommand("ebgp_multihop")
router_bgp__neighbor__ebgp_multihop.add_child(router_bgp__neighbor__ebgp_multihop_value)
router_bgp__neighbor__ebgp_multihop_value.set_variable_command(var_type="dec_integer", args=(1, 255))
router_bgp__neighbor__ebgp_multihop_value.set_result(new_config=("bgp", DynamicConfigSnippet(dynamic_list_name="neighbors", dynamic_arg="ebgp_multihop", master_arg="remote_ip", master=False)))
router_bgp__neighbor__ebgp_multihop_value.set_indent(2)
router_bgp__neighbor__ebgp_multihop_value.set_cli_command("ebgp-multihop")
router_bgp__neighbor__ebgp_multihop.set_cli_context_help("EBGP-multihop config for BGP neighbor")
router_bgp__neighbor__ebgp_multihop_value.set_cli_context_help("Max number of hops for EBGP neighbor")
router_bgp__neighbor__ebgp_multihop_value.set_cli_allowed_args("<1-255>")

router_bgp__neighbor__shutdown = DynamicConfigCommand("shutdown")
router_bgp__neighbor__shutdown.set_level(router_bgp__neighbor)
router_bgp__neighbor__shutdown.set_result(new_config=("bgp", DynamicConfigSnippet(dynamic_list_name="neighbors", dynamic_arg="shutdown", master_arg="remote_ip", master=False)))
router_bgp__neighbor__shutdown.set_deleter(DynamicDeleter(config_path=("bgp", "neighbors"), master_arg="remote_ip", delete_args="shutdown"))
router_bgp__neighbor__shutdown.set_indent(2)
router_bgp__neighbor__shutdown.set_cli_context_help("Shutdown BGP neighbor")



# sampling options
#    sampling interval <10-300 s>
#    sampling database <>
#    adjust interval <300-604800 s>
#    adjust threshold <1-100>


sampling = ConfigCommand("sampling")
sampling.set_cli_context_help("Bandwidth sampling commands")

sampling_options = ConfigCommand("options")
sampling.add_child(sampling_options)
sampling_options.set_cli_context_help("Bandwidth sampling options")
sampling_options.set_result(new_level=sampling_options)
sampling_options.set_deleter({'sampling': {'sampling_interval': 60, 'sampling_database': None, 'adjust_interval': 600, 'adjust_threshold': 10}})
sampling_options.set_cli_level("config-sampling-options")

sampling_options__sampling = ConfigCommand("sampling")
sampling_options__sampling.set_cli_context_help("Sampling settings")
sampling_options__sampling.set_level(sampling_options)
sampling_options__sampling_interval = ConfigCommand("interval")
sampling_options__sampling_interval.set_cli_context_help("Sampling interval")
sampling_options__sampling_interval.set_deleter({'sampling': {'sampling_interval': 60}})
sampling_options__sampling_interval_value = DynamicConfigCommand("sampling_interval")
sampling_options__sampling_interval_value.set_cli_context_help("Sampling interval in seconds")
sampling_options__sampling_interval_value.set_cli_allowed_args("<10-300>")

sampling_options__sampling_database = ConfigCommand("database")
sampling_options__sampling_database.set_cli_context_help("Sampling database file location")
sampling_options__sampling_database.set_deleter({'sampling': {'sampling_database': None}})
sampling_options__sampling_database_value = DynamicConfigCommand("sampling_database")
sampling_options__sampling_database_value.set_cli_context_help("Sampling database file location")
sampling_options__sampling_database_value.set_cli_allowed_args("<TEXT>")



sampling_options__adjust = ConfigCommand("adjust")
sampling_options__adjust.set_cli_context_help("Bandwidth adjustment settings")
sampling_options__adjust.set_level(sampling_options)
sampling_options__adjust_interval = ConfigCommand("interval")
sampling_options__adjust_interval.set_cli_context_help("Adjust interval")
sampling_options__adjust_interval.set_deleter({'sampling': {'adjust_interval': 600}})
sampling_options__adjust_interval_value = DynamicConfigCommand("adjust_interval")
sampling_options__adjust_interval_value.set_cli_context_help("Adjust interval in seconds")
sampling_options__adjust_interval_value.set_cli_allowed_args("<60-604800>")

sampling_options__adjust_threshold = ConfigCommand("threshold")
sampling_options__adjust_threshold.set_cli_context_help("Adjust threshold")
sampling_options__adjust_threshold.set_deleter({'sampling': {'adjust_threshold': 10}})
sampling_options__adjust_threshold_value = DynamicConfigCommand("adjust_threshold")
sampling_options__adjust_threshold_value.set_cli_context_help("Adjust threshold percentage")
sampling_options__adjust_threshold_value.set_cli_allowed_args("<1-100>")

sampling_options__sampling.add_child(sampling_options__sampling_interval)
sampling_options__sampling_interval.add_child(sampling_options__sampling_interval_value)
sampling_options__sampling.add_child(sampling_options__sampling_database)
sampling_options__sampling_database.add_child(sampling_options__sampling_database_value)
sampling_options__adjust.add_child(sampling_options__adjust_interval)
sampling_options__adjust_interval.add_child(sampling_options__adjust_interval_value)
sampling_options__adjust.add_child(sampling_options__adjust_threshold)
sampling_options__adjust_threshold.add_child(sampling_options__adjust_threshold_value)

sampling_options__sampling_interval_value.set_variable_command(var_type="dec_integer", args=(10, 300))
sampling_options__sampling_interval_value.set_result(new_config=("sampling", "sampling_interval"))
sampling_options__sampling_interval_value.set_indent(1)

sampling_options__sampling_database_value.set_variable_command(var_type="generic_string", args=(1, 255))
sampling_options__sampling_database_value.set_result(new_config=("sampling", "sampling_database"))
sampling_options__sampling_database_value.set_indent(1)

sampling_options__adjust_interval_value.set_variable_command(var_type="dec_integer", args=(60, 604800))
sampling_options__adjust_interval_value.set_result(new_config=("sampling", "adjust_interval"))
sampling_options__adjust_interval_value.set_indent(1)

sampling_options__adjust_threshold_value.set_variable_command(var_type="dec_integer", args=(1, 100))
sampling_options__adjust_threshold_value.set_result(new_config=("sampling", "adjust_threshold"))
sampling_options__adjust_threshold_value.set_indent(1)


# telemetry profiles
#    !
#    profile <name>
#       os [eos|iosxr|junos]
#       port <1-65535>
# 	    #protocol [eapi|gnmi] #currently only gnmi
# 	    auth [password|certificate] #currently only password
# 	    username <username>
# 	    password <password>


telemetry = ConfigCommand("telemetry")
telemetry.set_cli_context_help("Telemetry collection commands")

telemetry_profiles = ConfigCommand("profiles")
telemetry.add_child(telemetry_profiles)

telemetry_profiles.set_result(new_level=telemetry_profiles)
telemetry_profiles.set_deleter({'telemetry_profiles': []})
telemetry_profiles.set_cli_level("config-telemetry-profiles")
telemetry_profiles.set_cli_context_help("Telemetry profiles configuration mode")

telemetry_profiles__profile = ConfigCommand("profile")
telemetry_profiles__profile_value = DynamicConfigCommand("profile_name")
telemetry_profiles__profile_value.set_variable_command(var_type="generic_string", args=(1,255))
telemetry_profiles__profile_value.set_result(new_level=telemetry_profiles__profile, new_config=(DynamicConfigSnippet(dynamic_list_name="telemetry_profiles", dynamic_arg="profile_name", master=True)))
telemetry_profiles__profile_value.set_indent(1)
telemetry_profiles__profile_value.set_deleter(True)
telemetry_profiles__profile.add_child(telemetry_profiles__profile_value)
telemetry_profiles__profile.set_level(telemetry_profiles)
telemetry_profiles__profile.add_level(telemetry_profiles__profile)
telemetry_profiles__profile.set_cli_level("config-telemetry-profile")
telemetry_profiles__profile_value.set_cli_level("config-telemetry-profile")
telemetry_profiles__profile.set_upper_level(telemetry_profiles)
telemetry_profiles__profile_value.parent_owns_level = True
telemetry_profiles__profile.set_cli_context_help("Profile configuration mode")
telemetry_profiles__profile_value.set_cli_context_help("Telemetry profile")
telemetry_profiles__profile_value.set_cli_allowed_args("<PROFILE_NAME>")

telemetry_profiles__profile__os = ConfigCommand("os")
telemetry_profiles__profile__os.set_level(telemetry_profiles__profile)
telemetry_profiles__profile__os.set_deleter(DynamicDeleter(config_path="telemetry_profiles", master_arg="profile_name", delete_args="os"))
telemetry_profiles__profile__os_value = DynamicConfigCommand("os")
telemetry_profiles__profile__os_value.set_variable_command(var_type="specific_string", args=("eos", "iosxr", "junos"))
telemetry_profiles__profile__os_value.set_result(new_config=(DynamicConfigSnippet(dynamic_list_name="telemetry_profiles", dynamic_arg="os", master_arg="profile_name", master=False)))
telemetry_profiles__profile__os_value.set_indent(2)
telemetry_profiles__profile__os.add_child(telemetry_profiles__profile__os_value)
telemetry_profiles__profile__os.set_cli_context_help("OS to collect telemetry from")
telemetry_profiles__profile__os_value.set_cli_context_help("OS to collect telemetry from")
telemetry_profiles__profile__os_value.set_cli_allowed_args({"eos": "Arista EOS", "iosxr": "Cisco IOS-XR", "junos": "Juniper JUNOS"})

telemetry_profiles__profile__os_eos = ConfigCommand("eos")
telemetry_profiles__profile__os_eos.cli_helper = True
telemetry_profiles__profile__os_eos.cli_helped_command = telemetry_profiles__profile__os_value
telemetry_profiles__profile__os.cli_helpers.append(telemetry_profiles__profile__os_eos)
telemetry_profiles__profile__os_iosxr = ConfigCommand("iosxr")
telemetry_profiles__profile__os_iosxr.cli_helper = True
telemetry_profiles__profile__os_iosxr.cli_helped_command = telemetry_profiles__profile__os_value
telemetry_profiles__profile__os.cli_helpers.append(telemetry_profiles__profile__os_iosxr)
telemetry_profiles__profile__os_junos = ConfigCommand("junos")
telemetry_profiles__profile__os_junos.cli_helper = True
telemetry_profiles__profile__os_junos.cli_helped_command = telemetry_profiles__profile__os_value
telemetry_profiles__profile__os.cli_helpers.append(telemetry_profiles__profile__os_junos)

telemetry_profiles__profile__port = ConfigCommand("port")
telemetry_profiles__profile__port.set_level(telemetry_profiles__profile)
telemetry_profiles__profile__port.set_deleter(DynamicDeleter(config_path="telemetry_profiles", master_arg="profile_name", delete_args="port"))
telemetry_profiles__profile__port_value = DynamicConfigCommand("port")
telemetry_profiles__profile__port_value.set_variable_command(var_type="dec_integer", args=(1, 65535))
telemetry_profiles__profile__port_value.set_result(new_config=(DynamicConfigSnippet(dynamic_list_name="telemetry_profiles", dynamic_arg="port", master_arg="profile_name", master=False)))
telemetry_profiles__profile__port_value.set_indent(2)
telemetry_profiles__profile__port.add_child(telemetry_profiles__profile__port_value)
telemetry_profiles__profile__port.set_cli_context_help("Remote port for GNMI client")
telemetry_profiles__profile__port.set_cli_allowed_args("<1-65535>")

'''
telemetry_profiles__profile__protocol = ConfigCommand("protocol")
telemetry_profiles__profile__protocol.set_level(telemetry_profiles__profile)
telemetry_profiles__profile__protocol.set_deleter(DynamicDeleter(config_path="telemetry_profiles", master_arg="profile_name", delete_args="protocol"))
telemetry_profiles__profile__protocol_value = DynamicConfigCommand("protocol")
telemetry_profiles__profile__protocol_value.set_variable_command(var_type="specific_string", args=("eapi", "gnmi"))
telemetry_profiles__profile__protocol_value.set_result(new_config=(DynamicConfigSnippet(dynamic_list_name="telemetry_profiles", dynamic_arg="protocol", master_arg="profile_name", master=False)))
telemetry_profiles__profile__protocol_value.set_indent(2)
telemetry_profiles__profile__protocol.add_child(telemetry_profiles__profile__protocol_value)
telemetry_profiles__profile__protocol.set_cli_context_help("Protocol for telemetry collection")
telemetry_profiles__profile__protocol_value.set_cli_context_help("Protocol for telemetry collection")
telemetry_profiles__profile__protocol_value.set_cli_allowed_args({"eapi": "Arista eAPI", "gnmi": "GNMI"})

telemetry_profiles__profile__protocol_eapi = ConfigCommand("eapi")
telemetry_profiles__profile__protocol.cli_helper = True
telemetry_profiles__profile__protocol.cli_helped_command = telemetry_profiles__profile__protocol_value
telemetry_profiles__profile__protocol.cli_helpers.append(telemetry_profiles__profile__protocol_eapi)
telemetry_profiles__profile__protocol_gnmi = ConfigCommand("gnmi")
telemetry_profiles__profile__protocol.cli_helper = True
telemetry_profiles__profile__protocol.cli_helped_command = telemetry_profiles__profile__protocol_value
telemetry_profiles__profile__protocol.cli_helpers.append(telemetry_profiles__profile__protocol_gnmi)
'''

telemetry_profiles__profile__auth = ConfigCommand("auth")
telemetry_profiles__profile__auth.set_level(telemetry_profiles__profile)
telemetry_profiles__profile__auth.set_deleter(DynamicDeleter(config_path="telemetry_profiles", master_arg="profile_name", delete_args="auth"))
telemetry_profiles__profile__auth_value = DynamicConfigCommand("auth")
telemetry_profiles__profile__auth_value.set_variable_command(var_type="specific_string", args=("certificate", "password"))
telemetry_profiles__profile__auth_value.set_result(new_config=(DynamicConfigSnippet(dynamic_list_name="telemetry_profiles", dynamic_arg="auth", master_arg="profile_name", master=False)))
telemetry_profiles__profile__auth_value.set_indent(2)
telemetry_profiles__profile__auth.add_child(telemetry_profiles__profile__auth_value)
telemetry_profiles__profile__auth.set_cli_context_help("Authentication method")
telemetry_profiles__profile__auth_value.set_cli_context_help("Authentication method")
telemetry_profiles__profile__auth_value.set_cli_allowed_args({"certificate": "Use client certificate", "password": "Use password"})

telemetry_profiles__profile__auth_certificate = ConfigCommand("certificate")
telemetry_profiles__profile__auth_certificate.cli_helper = True
telemetry_profiles__profile__auth_certificate.cli_helped_command = telemetry_profiles__profile__auth_value
telemetry_profiles__profile__auth.cli_helpers.append(telemetry_profiles__profile__auth_certificate)
telemetry_profiles__profile__auth_password = ConfigCommand("password")
telemetry_profiles__profile__auth_password.cli_helper = True
telemetry_profiles__profile__auth_password.cli_helped_command = telemetry_profiles__profile__auth_value
telemetry_profiles__profile__auth.cli_helpers.append(telemetry_profiles__profile__auth_password)


telemetry_profiles__profile__username = ConfigCommand("username")
telemetry_profiles__profile__username.set_level(telemetry_profiles__profile)
telemetry_profiles__profile__username.set_deleter(DynamicDeleter(config_path="telemetry_profiles", master_arg="profile_name", delete_args="username"))
telemetry_profiles__profile__username_value = DynamicConfigCommand("username")
telemetry_profiles__profile__username_value.set_variable_command(var_type="generic_string", args=(1, 255))
telemetry_profiles__profile__username_value.set_result(new_config=(DynamicConfigSnippet(dynamic_list_name="telemetry_profiles", dynamic_arg="username", master_arg="profile_name", master=False)))
telemetry_profiles__profile__username_value.set_indent(2)
telemetry_profiles__profile__username.add_child(telemetry_profiles__profile__username_value)
telemetry_profiles__profile__username.set_cli_context_help("Username for remote device")
telemetry_profiles__profile__username.set_cli_allowed_args("<TEXT>")


telemetry_profiles__profile__password = ConfigCommand("password")
telemetry_profiles__profile__password.set_level(telemetry_profiles__profile)
telemetry_profiles__profile__password.set_deleter(DynamicDeleter(config_path="telemetry_profiles", master_arg="profile_name", delete_args="password"))
telemetry_profiles__profile__password_value = DynamicConfigCommand("password")
telemetry_profiles__profile__password_value.set_variable_command(var_type="generic_string", args=(1, 255))
telemetry_profiles__profile__password_value.set_result(new_config=(DynamicConfigSnippet(dynamic_list_name="telemetry_profiles", dynamic_arg="password", master_arg="profile_name", master=False)))
telemetry_profiles__profile__password_value.set_indent(2)
telemetry_profiles__profile__password.add_child(telemetry_profiles__profile__password_value)
telemetry_profiles__profile__password.set_cli_context_help("Password for remote device")
telemetry_profiles__profile__password.set_cli_allowed_args("<TEXT>")


# telemetry clients
#    !
#    group <name>
#       profile <name>
#       client <ipv4|ipv6>


telemetry_clients = ConfigCommand("clients")
telemetry.add_child(telemetry_clients)
telemetry_clients.set_result(new_level=telemetry_clients)
telemetry_clients.set_deleter({'telemetry_clients': []})
telemetry_clients.set_cli_level("config-telemetry-clients")
telemetry_clients.set_cli_context_help("Telemetry clients configuration mode")


telemetry_clients__group = ConfigCommand("group")
telemetry_clients__group_value = DynamicConfigCommand("client_group")
telemetry_clients__group_value.set_variable_command(var_type="generic_string", args=(1,255))
telemetry_clients__group_value.set_result(new_level=telemetry_clients__group, new_config=(DynamicConfigSnippet(dynamic_list_name="telemetry_clients", dynamic_arg="client_group", master=True, embedded_list="clients")))
telemetry_clients__group_value.set_indent(1)
telemetry_clients__group_value.set_deleter(True)
telemetry_clients__group.add_child(telemetry_clients__group_value)
telemetry_clients__group.set_level(telemetry_clients)
telemetry_clients__group.add_level(telemetry_clients__group)
telemetry_clients__group.set_cli_level("config-telemetry-clients-grp")
telemetry_clients__group_value.set_cli_level("config-telemetry-clients-grp")
telemetry_clients__group.set_upper_level(telemetry_clients)
telemetry_clients__group_value.parent_owns_level = True
telemetry_clients__group.set_cli_context_help("Telemetry clients group configuration mode")
telemetry_clients__group_value.set_cli_context_help("Client group name")
telemetry_clients__group_value.set_cli_allowed_args("<NAME>")

telemetry_clients__group__profile = ConfigCommand("profile")
telemetry_clients__group__profile.set_level(telemetry_clients__group)
telemetry_clients__group__profile.set_deleter(DynamicDeleter(config_path="telemetry_clients", master_arg="client_group", delete_args="profile"))
telemetry_clients__group__profile_value = DynamicConfigCommand("profile")
telemetry_clients__group__profile_value.set_variable_command(var_type="generic_string", args=(1, 255))
telemetry_clients__group__profile_value.set_result(new_config=(DynamicConfigSnippet(dynamic_list_name="telemetry_clients", dynamic_arg="profile", master_arg="client_group", master=False)))
telemetry_clients__group__profile_value.set_indent(2)
telemetry_clients__group__profile.add_child(telemetry_clients__group__profile_value)
telemetry_clients__group__profile.set_cli_context_help("Telemetry profile for this client group")
telemetry_clients__group__profile.set_cli_allowed_args("<TEXT>")

telemetry_clients__group__client = ConfigCommand("client")
telemetry_clients__group__client.set_level(telemetry_clients__group)
telemetry_clients__group__client_value = DynamicConfigCommand("remote_ip")
telemetry_clients__group__client.add_child(telemetry_clients__group__client_value)
telemetry_clients__group__client_value.set_variable_command(var_type="ip", args=None)
telemetry_clients__group__client_value.set_result(new_config=(DynamicConfigSnippet(dynamic_list_name="telemetry_clients", dynamic_arg="clients", master_arg="client_group", master=False),
DynamicConfigSnippet(dynamic_list_name="clients", dynamic_arg="remote_ip", master=True, nested=True)))
telemetry_clients__group__client_value.set_indent(2)
telemetry_clients__group__client_value.set_deleter(True)
telemetry_clients__group__client.set_cli_context_help("Set telemetry client IP")
telemetry_clients__group__client_value.set_cli_context_help("Client IP")
telemetry_clients__group__client_value.set_cli_allowed_args("<ipv4|ipv6>")



# management api http-commands
#    !
#    protocol http
#       port <1-65535>
#       shutdown
#    !
#    protocol https
#       port <1-65535>
#       certificate <> key <>
#       shutdown


management = ConfigCommand("management")
management.set_cli_context_help("Management commands")
management_api = ConfigCommand("api")
management_api_http_commands = ConfigCommand("http-commands")
management.add_child(management_api)
management_api.add_child(management_api_http_commands)
management_api.set_cli_context_help("API configuration")
management_api_http_commands.set_cli_context_help("HTTP-commands API configuration mode")

management_api_http_commands.set_result(new_level=management_api_http_commands)
management_api_http_commands.set_deleter({'management': {'http-commands': {'http': {'port': 8080, 'shutdown': True}, 'https': {'port': 8443, 'shutdown': True, 'certificate': None, 'key': None}}}})
management_api_http_commands.set_cli_level("config-mgmt-api-http-cmds")


management_api_http_commands__protocol = ConfigCommand("protocol")
management_api_http_commands__protocol.set_level(management_api_http_commands)
management_api_http_commands__protocol_http = ConfigCommand("http")
management_api_http_commands__protocol.add_child(management_api_http_commands__protocol_http)
management_api_http_commands__protocol_http.set_result(new_level=management_api_http_commands__protocol_http)
management_api_http_commands__protocol_http.set_deleter({'management': {'http-commands': {'http': {'port': 80, 'shutdown': True}}}})
management_api_http_commands__protocol_http.set_indent(1)
management_api_http_commands__protocol_http.set_cli_level("config-mgmt-api-http-cmds-http")
management_api_http_commands__protocol_http.set_upper_level(management_api_http_commands)

management_api_http_commands__protocol.set_cli_context_help("API protocol")
management_api_http_commands__protocol_http.set_cli_context_help("HTTP API configuration mode")

management_api_http_commands__protocol_http__port = ConfigCommand("port")
management_api_http_commands__protocol_http__port.set_level(management_api_http_commands__protocol_http)
management_api_http_commands__protocol_http__port_value = DynamicConfigCommand("port")
management_api_http_commands__protocol_http__port.add_child(management_api_http_commands__protocol_http__port_value)
management_api_http_commands__protocol_http__port.set_deleter({'management': {'http-commands': {'http': {'port': 8080}}}})
management_api_http_commands__protocol_http__port_value.set_variable_command(var_type="dec_integer", args=(1, 65535))
management_api_http_commands__protocol_http__port_value.set_result(new_config=("management", "http-commands", "http", "port"))
management_api_http_commands__protocol_http__port_value.set_indent(2)
management_api_http_commands__protocol_http__port.set_cli_context_help("Set HTTP API port")
management_api_http_commands__protocol_http__port_value.set_cli_context_help("HTTP API port value")
management_api_http_commands__protocol_http__port_value.set_cli_allowed_args("<1-65535>")

management_api_http_commands__protocol_http__shutdown = DynamicConfigCommand("shutdown")
management_api_http_commands__protocol_http__shutdown.set_level(management_api_http_commands__protocol_http)
management_api_http_commands__protocol_http__shutdown.set_result(new_config=("management", "http-commands", "http", "shutdown"))
management_api_http_commands__protocol_http__shutdown.set_deleter({'management': {'http-commands': {'http': {'shutdown': False}}}})
management_api_http_commands__protocol_http__shutdown.set_indent(2)
management_api_http_commands__protocol_http__shutdown.set_cli_context_help("Shutdown HTTP API")

management_api_http_commands__protocol_https = ConfigCommand("https")
management_api_http_commands__protocol.add_child(management_api_http_commands__protocol_https)
management_api_http_commands__protocol_https.set_result(new_level=management_api_http_commands__protocol_https)
management_api_http_commands__protocol_https.set_deleter({'management': {'http-commands': {'https': {'port': 8443, 'shutdown': True, 'certificate': None, 'key': None}}}})
management_api_http_commands__protocol_https.set_indent(1)
management_api_http_commands__protocol_https.set_cli_level("config-mgmt-api-http-cmds-https")
management_api_http_commands__protocol_https.set_upper_level(management_api_http_commands)
management_api_http_commands__protocol_https.set_cli_context_help("HTTPS API configuration mode")

management_api_http_commands__protocol.add_level(management_api_http_commands__protocol_http)
management_api_http_commands__protocol.add_level(management_api_http_commands__protocol_https)

management_api_http_commands__protocol_https__port = ConfigCommand("port")
management_api_http_commands__protocol_https__port.set_level(management_api_http_commands__protocol_https)
management_api_http_commands__protocol_https__port_value = DynamicConfigCommand("port")
management_api_http_commands__protocol_https__port.add_child(management_api_http_commands__protocol_https__port_value)
management_api_http_commands__protocol_https__port.set_deleter({'management': {'http-commands': {'https': {'port': 8443}}}})
management_api_http_commands__protocol_https__port_value.set_variable_command(var_type="dec_integer", args=(1, 65535))
management_api_http_commands__protocol_https__port_value.set_result(new_config=("management", "http-commands", "https", "port"))
management_api_http_commands__protocol_https__port_value.set_indent(2)
management_api_http_commands__protocol_https__port.set_cli_context_help("Set HTTPS API port")
management_api_http_commands__protocol_https__port_value.set_cli_context_help("HTTPS API port value")
management_api_http_commands__protocol_https__port_value.set_cli_allowed_args("<1-65535>")

management_api_http_commands__protocol_https__shutdown = DynamicConfigCommand("shutdown")
management_api_http_commands__protocol_https__shutdown.set_level(management_api_http_commands__protocol_https)
management_api_http_commands__protocol_https__shutdown.set_result(new_config=("management", "http-commands", "https", "shutdown"))
management_api_http_commands__protocol_https__shutdown.set_deleter({'management': {'http-commands': {'https': {'shutdown': False}}}})
management_api_http_commands__protocol_https__shutdown.set_indent(2)
management_api_http_commands__protocol_https__shutdown.set_cli_context_help("Shutdown HTTPS API")


management_api_http_commands__protocol_https__certificate = ConfigCommand("certificate")
management_api_http_commands__protocol_https__certificate.set_level(management_api_http_commands__protocol_https)
management_api_http_commands__protocol_https__certificate.set_deleter({'management': {'http-commands': {'https': {'certificate': None, 'key': None}}}})
management_api_http_commands__protocol_https__certificate_value = DynamicConfigCommand("certificate")
management_api_http_commands__protocol_https__certificate.add_child(management_api_http_commands__protocol_https__certificate_value)
management_api_http_commands__protocol_https__certificate_value.set_variable_command(var_type="generic_string", args=(1,255))
management_api_http_commands__protocol_https__certificate_value.set_result(new_config=("management", "http-commands", "https", "certificate"))
management_api_http_commands__protocol_https__certificate_value.set_indent(2)
management_api_http_commands__protocol_https__certificate.set_cli_context_help("Set TLS certificate for HTTPS API")
management_api_http_commands__protocol_https__certificate_value.set_cli_context_help("Path to TLS certificate")
management_api_http_commands__protocol_https__certificate_value.set_cli_allowed_args("<PATH>")

management_api_http_commands__protocol_https__certificate_value_key = ConfigCommand("key")
management_api_http_commands__protocol_https__certificate_value.add_child(management_api_http_commands__protocol_https__certificate_value_key)
management_api_http_commands__protocol_https__certificate_value_key_value = DynamicConfigCommand("key")
management_api_http_commands__protocol_https__certificate_value_key.add_child(management_api_http_commands__protocol_https__certificate_value_key_value)
management_api_http_commands__protocol_https__certificate_value_key_value.set_variable_command(var_type="generic_string", args=(1,255))
management_api_http_commands__protocol_https__certificate_value_key_value.set_result(new_config=("management", "http-commands", "https", "key"))
management_api_http_commands__protocol_https__certificate_value_key.set_cli_context_help("Set TLS key for HTTPS API")
management_api_http_commands__protocol_https__certificate_value_key_value.set_cli_context_help("Path to TLS key")
management_api_http_commands__protocol_https__certificate_value_key_value.set_cli_allowed_args("<PATH>")


# management syslog
#    ! 
#    host <ipv4|ipv6>
#       protocol [udp|tcp]
#       port <1-65535>


management_syslog = ConfigCommand("syslog")
management.add_child(management_syslog)
management_syslog.set_deleter({'syslog': {'hosts': []}})
management_syslog.set_result(new_level=management_syslog)
management_syslog.set_cli_level("config-mgmt-syslog")
management_syslog.set_cli_context_help("Syslog configuration mode")

management_syslog__host = ConfigCommand("host")
management_syslog__host.set_level(management_syslog)
management_syslog__host.add_level(management_syslog__host)
management_syslog__host_value = DynamicConfigCommand("remote_ip")
management_syslog__host_value.set_deleter(True)
management_syslog__host.add_child(management_syslog__host_value)
management_syslog__host_value.set_variable_command(var_type="ip", args=None)
management_syslog__host_value.set_result(new_level=management_syslog__host, new_config=("syslog", DynamicConfigSnippet(dynamic_list_name="hosts", dynamic_arg="remote_ip", master=True)))
management_syslog__host_value.set_indent(1)
management_syslog__host_value.set_cli_level("config-mgmt-syslog-host")
management_syslog__host.set_upper_level(management_syslog)
management_syslog__host_value.parent_owns_level = True
management_syslog__host.set_cli_context_help("Syslog remote host configuration mode")
management_syslog__host_value.set_cli_context_help("IP address of remote syslog host")
management_syslog__host_value.set_cli_allowed_args("<ipv4|ipv6>")

management_syslog__host__protocol = ConfigCommand("protocol")
management_syslog__host__protocol.set_level(management_syslog__host)
management_syslog__host__protocol_value = DynamicConfigCommand("protocol")
management_syslog__host__protocol.add_child(management_syslog__host__protocol_value)
management_syslog__host__protocol_value.set_variable_command(var_type="specific_string", args=("udp", "tcp"))
management_syslog__host__protocol_value.set_result(new_config=("syslog", DynamicConfigSnippet(dynamic_list_name="hosts", dynamic_arg="protocol", master_arg="remote_ip", master=False)))
management_syslog__host__protocol_value.set_indent(2)
management_syslog__host__protocol.set_deleter(DynamicDeleter(config_path=("syslog", "hosts"), master_arg="remote_ip", delete_args="protocol"))
management_syslog__host__protocol.set_cli_context_help("Transport protocol for syslog host")
management_syslog__host__protocol_value.set_cli_context_help("Transport protocol for syslog host")
management_syslog__host__protocol_value.set_cli_allowed_args({"udp": "Send syslog data using UDP", "tcp": "Send syslog data using TCP"})

management_syslog__host__protocol_udp = ConfigCommand("udp")
management_syslog__host__protocol_udp.cli_helper = True
management_syslog__host__protocol_udp.cli_helped_command = management_syslog__host__protocol_value
management_syslog__host__protocol_tcp = ConfigCommand("tcp")
management_syslog__host__protocol_tcp.cli_helper = True
management_syslog__host__protocol_tcp.cli_helped_command = management_syslog__host__protocol_value
management_syslog__host__protocol.cli_helpers.append(management_syslog__host__protocol_udp)
management_syslog__host__protocol.cli_helpers.append(management_syslog__host__protocol_tcp)

management_syslog__host__port = ConfigCommand("port")
management_syslog__host__port.set_level(management_syslog__host)
management_syslog__host__port_value = DynamicConfigCommand("port")
management_syslog__host__port.add_child(management_syslog__host__port_value)
management_syslog__host__port_value.set_variable_command(var_type="dec_integer", args=(1, 65535))
management_syslog__host__port_value.set_result(new_config=("syslog", DynamicConfigSnippet(dynamic_list_name="hosts", dynamic_arg="port", master_arg="remote_ip", master=False)))
management_syslog__host__port_value.set_indent(2)
management_syslog__host__port.set_deleter(DynamicDeleter(config_path=("syslog", "hosts"), master_arg="remote_ip", delete_args="port"))
management_syslog__host__port.set_cli_context_help("Set port for syslog host")
management_syslog__host__port_value.set_cli_context_help("Port of remote syslog host")
management_syslog__host__port_value.set_cli_allowed_args("<1-65535>")



# management users
#    !
#    user <username>
#       password [cleartext|encrypted] <>


management_users = ConfigCommand("users")
management_users.set_cli_context_help("Users configuration")
management_users.set_result(new_level=management_users)
management_users.set_deleter({'users': {'users': []}})
management_users.set_cli_level("config-mgmt-users")
management.add_child(management_users)

management_users__user = ConfigCommand("user")
management_users__user.set_cli_context_help("User config mode")
management_users__user.set_level(management_users)
management_users__user.add_level(management_users__user)

management_users__user_value = DynamicConfigCommand("username")
management_users__user_value.set_deleter(True)
management_users__user.add_child(management_users__user_value)
management_users__user_value.set_variable_command(var_type="generic_string", args=(1, 255))
management_users__user_value.set_result(new_level=management_users__user, new_config=("users", DynamicConfigSnippet(dynamic_list_name="users", dynamic_arg="username", master=True)))
management_users__user_value.set_indent(1)
management_users__user_value.set_cli_level("config-mgmt-username")
management_users__user.set_upper_level(management_users)
management_users__user_value.parent_owns_level = True
management_users__user_value.set_cli_context_help("Username for the user")
management_users__user_value.set_cli_allowed_args("<TEXT>")

management_users__user__password = ConfigCommand("password")
management_users__user__password.set_level(management_users__user)
management_users__user__password.set_deleter(DynamicDeleter(config_path=("users", "users"), master_arg="username", delete_args="password"))
management_users__user__password.set_cli_context_help("Password for user")

management_users__user__password_cleartext = ConfigCommand("cleartext")
management_users__user__password.add_child(management_users__user__password_cleartext)
management_users__user__password_cleartext.set_cli_context_help("Clear password will follow")
management_users__user__password_cleartext_value = DynamicConfigCommand("password")
management_users__user__password_cleartext_value.set_indent(2)
management_users__user__password_cleartext.add_child(management_users__user__password_cleartext_value)
management_users__user__password_cleartext_value.set_variable_command(var_type="generic_string", args=(1, 255))
management_users__user__password_cleartext_value.set_result(new_config=("users", DynamicConfigSnippet(dynamic_list_name="users", dynamic_arg="password", master_arg="username", master=False)))
management_users__user__password_cleartext_value.set_cli_context_help("Enter cleartext password")
management_users__user__password_cleartext_value.set_cli_allowed_args("<TEXT>")
management_users__user__password_cleartext_value.set_encrypt()

management_users__user__password_encrypted = ConfigCommand("encrypted")
management_users__user__password.add_child(management_users__user__password_encrypted)
management_users__user__password_encrypted.set_cli_context_help("Encrypted password will follow")
management_users__user__password_encrypted_value = DynamicConfigCommand("password")
management_users__user__password_encrypted_value.set_indent(2)
management_users__user__password_encrypted.add_child(management_users__user__password_encrypted_value)
management_users__user__password_encrypted_value.set_variable_command(var_type="generic_string", args=(1, 255))
management_users__user__password_encrypted_value.set_result(new_config=("users", DynamicConfigSnippet(dynamic_list_name="users", dynamic_arg="password", master_arg="username", master=False)))
management_users__user__password_encrypted_value.set_cli_context_help("Enter encrypted password")
management_users__user__password_encrypted_value.set_cli_allowed_args("<TEXT>")



global_commands = [router, sampling, telemetry, management]

level_reset_commands = [sampling_options, 
                        router_bgp_asn,
                        telemetry_profiles,
                        telemetry_clients,
                        management_api_http_commands, 
                        management_syslog, 
                        management_users, 
                        ]

class ConfigHandler:
    def __init__(self, default_config):
        self.config = copy.deepcopy(default_config)
        self.startup_config = 'startup-config'
        self.logger = logging.getLogger("config_handler")


    def parse_config_line(self, config_line):
        self.logger.debug(f'Config-handler: Parsing config line {config_line}')
        config_update = None
        master_arg = None
        parsed_line = config_line.split()
        previous_command = None
        command_applied = False
        exclusive = False
        exclusive_item = None

        if parsed_line[0] == "no" and len(parsed_line) > 1:
            parsed_line = parsed_line[1:]
            while len(parsed_line) > 0:
                command = parsed_line.pop(0)
                if not previous_command:
                    # if a command (under hierarchy is the same as a global command - e.g. "ipv4", "ipv6")
                    skip_global_commands = False
                    if self.level:
                        for item in self.level.nested_commands:
                            if item.command == command:
                                skip_global_commands = True
                    if not skip_global_commands:
                        for item in global_commands:
                            if item.command == command:
                                if item.deleter:
                                    self.logger.debug(f'Config-handler: Updating config with deleter {str(item.deleter)}')
                                    self.config = update_dictionary(self.config, item.deleter)
                                    return True, item.deleter
                                previous_command = item
                                command = parsed_line.pop(0)
                if not previous_command:
                    for item in self.level.nested_commands:
                        if item.command == command:
                            if item.deleter:
                                if isinstance(item.deleter, DynamicDeleter):
                                    config_deleter = None
                                    config_removed = False
                                    if isinstance(item.deleter.config_path, tuple):
                                        config_path = list(item.deleter.config_path)
                                        last_arg = item.deleter.config_path[-1]
                                    else:
                                        config_path = [item.deleter.config_path]
                                        last_arg = item.deleter.config_path
                                    while len(config_path) > 0:
                                        arg = config_path.pop(0)
                                        if not config_deleter:
                                            config_deleter = self.config[arg]
                                            if item.deleter.grandmaster_arg:
                                                for config_deleter_part in config_deleter:
                                                    if config_deleter_part[item.deleter.grandmaster_arg] == self.grandmaster_snippet[arg][0][item.deleter.grandmaster_arg]:
                                                        config_deleter = config_deleter_part
                                        else:
                                            config_deleter = config_deleter[arg]
                                    for config_item in config_deleter:
                                        if config_item[item.deleter.master_arg] == self.master_snippet[last_arg][0][item.deleter.master_arg]:
                                            if isinstance(item.deleter.delete_args, tuple):
                                                for delete_arg in item.deleter.delete_args:
                                                    if delete_arg in config_item.keys():
                                                        del config_item[delete_arg]
                                            else:                                              
                                                if item.deleter.delete_args in config_item.keys():
                                                    del config_item[item.deleter.delete_args]
                                            config_removed = True
                                    if config_removed:
                                        self.logger.debug(f'Config-handler: Removing config with deleter {str(config_deleter)}')
                                        return True, config_deleter
                                else:
                                    self.logger.debug(f'Config-handler: Updating config with deleter {str(item.deleter)}')
                                    self.config = update_dictionary(self.config, item.deleter)
                                    return True, item.deleter
                            previous_command = item
                else:
                    for item in previous_command.children:
                        if item.command == command and item.deleter:
                            if isinstance(item.deleter, dict):
                                self.logger.debug(f'Config-handler: Updating config with deleter {str(item.deleter)}')
                                self.config = update_dictionary(self.config, item.deleter)
                                return True, item.deleter
                            config_deleter = None
                            config_removed = False
                            if isinstance(item.deleter.config_path, tuple):
                                config_path = list(item.deleter.config_path)
                                last_arg = item.deleter.config_path[-1]
                            else:
                                config_path = [item.deleter.config_path]
                                last_arg = item.deleter.config_path
                            while len(config_path) > 0:
                                arg = config_path.pop(0)
                                if not config_deleter:
                                    config_deleter = self.config[arg]
                                else:
                                    config_deleter = config_deleter[arg]
                                for config_item in config_deleter:
                                    if config_item[item.deleter.master_arg] == self.master_snippet[last_arg][0][item.deleter.master_arg]:
                                        if isinstance(item.deleter.delete_args, tuple):
                                            for delete_arg in item.deleter.delete_args:
                                                if delete_arg in config_item.keys():
                                                    del config_item[delete_arg]
                                        else:
                                            if item.deleter.delete_args in config_item.keys():
                                                del config_item[item.deleter.delete_args]
                                        config_removed = True
                                if config_removed:
                                    self.logger.debug(f'Config-handler: Removing config with deleter {str(item.deleter)}')
                                    return True, config_deleter
                        elif type(item) is DynamicConfigCommand and item.deleter:
                            #config_deleter = copy.deepcopy(self.config)
                            config_deleter = None
                            config_removed = False
                            if isinstance(item.new_config, DynamicConfigSnippet):
                                if item.new_config.master:
                                    config_deleter = self.config[item.new_config.dynamic_list_name]
                                    for config_item in config_deleter:
                                        if config_item[item.new_config.dynamic_arg] == command:
                                            config_deleter.remove(config_item)
                                            config_removed = True
                                else:
                                    self.logger.error(f'Config-handler: When processing command {item.command} got to a strange place where it shouldnt get')
                                    #print("hier")
                                    #print(item.command)
                            else:
                                config_deleter = None
                                new_config_list = list(item.new_config)
                                while len(new_config_list) > 0:
                                    config_snippet = new_config_list.pop(0)
                                    if not isinstance(config_snippet, DynamicConfigSnippet):
                                        config_deleter = self.config[config_snippet]
                                    elif config_snippet.master:
                                        config_deleter = config_deleter[config_snippet.dynamic_list_name]
                                        for config_item in config_deleter:
                                            if config_item[config_snippet.dynamic_arg] == command:
                                                config_deleter.remove(config_item)
                                                config_removed = True
                                                # added to fix affinity maps removal
                                                if config_removed:
                                                    self.logger.debug(f'Config-handler: Removing config with deleter {str(config_deleter)}')
                                                    return True, config_deleter
                                    else:
                                        if not config_deleter:
                                            config_deleter = self.config
                                        for config_item in config_deleter[config_snippet.dynamic_list_name]:
                                            if config_snippet.dynamic_list_name not in self.master_snippet.keys():
                                                # for nested config snippets - e.g. delete affinity from traffic_eng_nodes
                                                if config_item[config_snippet.master_arg] == self.grandmaster_snippet[config_snippet.dynamic_list_name][0][config_snippet.master_arg]:
                                                    config_deleter = self.grandmaster_snippet[config_snippet.dynamic_list_name][0]
                                                    break
                                                continue
                                            if config_item[config_snippet.master_arg] == self.master_snippet[config_snippet.dynamic_list_name][0][config_snippet.master_arg]:
                                                try:
                                                    if isinstance(config_item[item.command], list):
                                                        if command in config_item[item.command]:
                                                            config_item[item.command].remove(command)
                                                            config_removed = True
                                                    else:
                                                        self.logger.error(f'Config-handler: When processing command {command} got to a strange place where it shouldnt get')
                                                        #print(command)
                                                except KeyError:
                                                    if isinstance(config_item[config_snippet.dynamic_arg], list):
                                                        #print(config_item)
                                                        #print(config_snippet.dynamic_arg)
                                                        for embedded_item in config_item[config_snippet.dynamic_arg]:
                                                            if isinstance(embedded_item[item.command], int):
                                                                try:
                                                                    command = int(command)
                                                                except:
                                                                    pass
                                                            if embedded_item[item.command] == command:
                                                                config_item[config_snippet.dynamic_arg].remove(embedded_item)
                                                                config_removed = True
                                                                # returning here as workaround for weird bug
                                                                if config_removed:
                                                                    self.logger.debug(f'Config-handler: Removing config with deleter {str(config_deleter)}')
                                                                    return True, config_deleter
                                                    else:
                                                        print(command)
                        else:
                            if item.command == command:
                                previous_command = item
            if config_removed:
                return True, config_deleter

            return False, None



        if parsed_line[0] == "end" and len(parsed_line) == 0:
            self.logger.debug(f'Config-handler: Exiting config mode')
            self.init_config()

        self.logger.debug(f'Config-handler: Trying to process config line {parsed_line}')
        while len(parsed_line) > 0:
            command = parsed_line.pop(0)
            if not previous_command:
                # if a command (under hierarchy is the same as a global command - e.g. "ipv4", "ipv6")
                skip_global_commands = False
                if self.level:
                    for item in self.level.nested_commands:
                        if item.command == command:
                            skip_global_commands = True
                if not skip_global_commands:
                    for item in global_commands:
                        if item.command == command:
                            previous_command = item
            if not previous_command:
                for item in self.level.nested_commands:
                    if item.command == command:
                        if item.exclusive == True:
                            exclusive = True
                            exclusive_item = item
                        if len(parsed_line) == 0:
                            if item.command == command:
                                command_applied = False
                                config_update = None
                                if isinstance(item, DynamicConfigCommand):
                                    if isinstance(item.new_config, tuple):
                                        new_config_list = list(item.new_config)
                                    else:
                                        new_config_list = [item.new_config]
                                else:
                                    new_config_list = []
                                while len(new_config_list) > 0:
                                    config_snippet = new_config_list.pop(0)
                                    if not isinstance(config_snippet, DynamicConfigSnippet):
                                        if not config_update:
                                            config_update = self.config[config_snippet]
                                        else:
                                            # handle shutdown under management api
                                            if config_snippet == item.command:
                                                config_update[config_snippet] = True
                                                command_applied = True
                                                self.logger.debug(f'Config-handler: Applied command {item.command}')
                                            else:
                                                config_update = config_update[config_snippet]
                                    else:
                                        if not config_update:
                                            config_update = self.config
                                        for config_item in config_update[config_snippet.dynamic_list_name]:
                                            if config_item[config_snippet.master_arg] == self.master_snippet[config_snippet.dynamic_list_name][0][config_snippet.master_arg]:                                              
                                                config_item[item.command] = True
                                                command_applied = True
                                                self.logger.debug(f'Config-handler: Applied command {item.command}')
                                if item.new_level:
                                    self.level = item.new_level
                                    command_applied = True
                                    self.logger.debug(f'Config-handler: Applied command {item.command}, updated current level')
                                return command_applied, config_update
                        else:
                            previous_command = item
                if not previous_command:
                    pass
                    #print(f'Incorrect config {config_line}')
            
            else:
                if len(previous_command.children) == 0:
                    self.master_snippet = copy.deepcopy(self.master_snippet_old)
                    self.logger.error(f'Config-handler: Incorrect config "{config_line}"')
                    command_applied = False
                    return command_applied, None
                for item in previous_command.children:
                    if type(item) is DynamicConfigCommand:
                        if len(item.children) > 0 and len(parsed_line) == 0:
                            # handle old config disjoint-group <> after new arguments in TD v1.7
                            if item.command == "disjoint_group_id":
                                parsed_line.append("link")
                            else:
                                self.logger.error(f'Config-handler: Incorrect config "{config_line}"')
                                command_applied = False
                                return command_applied, None
                        try:
                            if item.immutable is True:
                                # ultra bydlokod only for router bgp for now
                                if self.config[item.new_config[0]][item.new_config[1]]:
                                    if str(self.config[item.new_config[0]][item.new_config[1]]) != command:
                                        command_applied = False
                                        self.logger.debug(f'Config-handler: Unable to change immutable config {command}')
                                        return command_applied, None
                            if exclusive is True:
                                self.logger.debug(f'Config-handler: Handling exclusive command {command}')
                                # boilerplate code to handle exclusive commands e.g. "install" under TE policy
                                config_deleter = None
                                config_removed = False
                                if isinstance(exclusive_item.deleter.config_path, tuple):
                                    config_path = list(exclusive_item.deleter.config_path)
                                    last_arg = exclusive_item.deleter.config_path[-1]
                                else:
                                    config_path = [exclusive_item.deleter.config_path]
                                    last_arg = exclusive_item.deleter.config_path
                                while len(config_path) > 0:
                                    arg = config_path.pop(0)
                                    if not config_deleter:
                                        config_deleter = self.config[arg]
                                        if exclusive_item.deleter.grandmaster_arg:
                                            for config_deleter_part in config_deleter:
                                                if config_deleter_part[exclusive_item.deleter.grandmaster_arg] == self.grandmaster_snippet[arg][0][exclusive_item.deleter.grandmaster_arg]:
                                                    config_deleter = config_deleter_part
                                    else:
                                        config_deleter = config_deleter[arg]
                                for config_item in config_deleter:
                                    if config_item[exclusive_item.deleter.master_arg] == self.master_snippet[last_arg][0][exclusive_item.deleter.master_arg]:
                                        if isinstance(exclusive_item.deleter.delete_args, tuple):
                                            for delete_arg in exclusive_item.deleter.delete_args:
                                                if delete_arg in config_item.keys():
                                                    del config_item[delete_arg]
                                        else:                                              
                                            if exclusive_item.deleter.delete_args in config_item.keys():
                                                del config_item[exclusive_item.deleter.delete_args]
                                exclusive = False
                                exclusive_item = None
                            config_update, self.master_snippet, self.grandmaster_snippet, master_arg, grandmaster_arg = item.apply_command(command, self.master_snippet, self.grandmaster_snippet)
                        except ValueError:
                            self.logger.error(f'Config-handler: Incorrect config "{config_line}"')
                            command_applied = False
                            return command_applied, None
                        if item.new_level:
                            self.level = item.new_level
                            if item in level_reset_commands:
                                if item.command != "ipv4 access-list" and item.command != "ipv6 access-list":
                                    self.master_snippet = None                        
                        command_applied = True
                        previous_command = item
                    else:
                        if item.command == command:
                            if len(parsed_line) == 0:
                                if item.new_level:
                                    self.level = item.new_level
                                    if item in level_reset_commands:
                                        if item.command != "ipv4 access-list" and item.command != "ipv6 access-list":
                                            self.master_snippet = None
                                if item.new_config:
                                    self.logger.error(f'Config-handler: Got to a strange place with new_config {str(item.new_config)}')
                                command_applied = True
                            previous_command = item
        if command_applied:
            self.master_snippet_old = copy.deepcopy(self.master_snippet)
        if config_update:
            self.logger.debug(f'Config-handler: Returning config update {str(config_update)}')
            self.config = update_dictionary(self.config, config_update, master_arg, grandmaster_arg)
            return command_applied, config_update
        return command_applied, None


    def init_config(self):
        self.level = None
        self.master_snippet = None
        self.master_snippet_old = None
        self.grandmaster_snippet = None


    def swap_config(self, new_config):
        self.config = copy.deepcopy(new_config)


    def apply_command_without_diff(self, command):
        command = command.strip()
        if command[0] == "!":
            return True
        try:
            self.logger.debug(f'Config-handler: Applying config command "{command}"')
            command_applied, _ = self.parse_config_line(command)
            # temporary hack to ensure idempotency with "no" commands
            if len(command) > 2:
                if command[:2] == "no":
                    return True
        except Exception as e:
            # temporary hack to ensure idempotency with "no" commands
            if len(command) > 2:
                if command[:2] == "no":
                    return True
            self.logger.error(f'Config-handler: Failed to apply command "{command}", exception {e.__class__.__name__, e.args}')
            return False
        if not command_applied:
            return False
        
        return True


    def apply_command(self, command):

        old_config = copy.deepcopy(self.config)
        config_update = None
        command_result = {}
        command = command.strip()
        if command[0] == "!":
            return command_result, config_update
        try:
            self.logger.debug(f'Config-handler: Applying config command "{command}"')
            command_applied, config_update = self.parse_config_line(command)
        except Exception as e:
            self.logger.error(f'Config-handler: Failed to apply command "{command}", exception {e.__class__.__name__, e.args}')
            command_result = False
            return command_result, config_update
        if not command_applied:
            command_result = False
            return command_result, config_update
        #if not DeepDiff(old_config, self.config, ignore_order=True):
        #    return command_result, None
        #config_update = DeepDiff(old_config, self.config, ignore_order=True)
        config_diff = DeepDiff(old_config, self.config, ignore_order=True)
        return command_result, config_diff
        
        #return command_result, config_update

    
    def read_config_lines(self, config_lines):

        self.init_config()

        for line in config_lines:
            try:
                self.parse_config_line(line)
            except Exception as e:
                self.logger.error(f'Config-handler: Failed to parse config line "{line}", exception {e.__class__.__name__, e.args}')


    def read_startup_config(self):
        try:
            with open(self.startup_config) as f:
                lines = f.readlines()
        except Exception as e:
            self.logger.error(f'Config-handler: Unable to read startup-config, exception {e.__class__.__name__, e.args}; using default config')
            return

        config_lines = []
        for line in lines:
            line = line.strip()
            if len(line) == 0: continue
            if line[0] == "!": continue
            config_lines.append(line)

        self.read_config_lines(config_lines)
        self.logger.info(f'Config-handler: Loaded config from file {self.startup_config}')





    CONFIG_SECTIONS = {
        "bgp": router_bgp,
        "sampling": sampling_options,
        "telemetry_profiles": telemetry_profiles,
        "telemetry_clients": telemetry_clients,
        "management": management_api_http_commands,
        "syslog": management_syslog,
        "users": management_users,
    }

    @staticmethod
    def unpack_parent(config_list, command):
        if not command.parent:
            return config_list
        else:
            config_list.insert(0, command.parent.command)
            config_list = ConfigHandler.unpack_parent(config_list, command.parent)


    @staticmethod
    def unpack_list(unpacked_list, command, config_data):
        # explicit path indexes
        if len(command.nested_commands) == 0:
            for config_data_part in config_data:
                unpacked_list = ConfigHandler.unpack_command(unpacked_list, command, config_data_part)
            return unpacked_list
        indent = 0
        # temporary hack to print affinity map and srlg map nicer
        affinity_printed = False
        srlg_printed = False
        for config_data_part in config_data:
            for child in command.children:
                indent = child.indent
            # for some reason it was printing to many !!! after affinity-map
            if "affinity_name" in config_data_part.keys():
                if indent == 0: continue
                if not affinity_printed:
                    unpacked_list.append("   " * indent + "!")
                    affinity_printed = True
            elif "srlg_name" in config_data_part.keys():
                if indent == 0: continue
                if not srlg_printed:
                    unpacked_list.append("   " * indent + "!")
                    srlg_printed = True
            else:
                unpacked_list.append("   " * indent + "!")
            for nested_command in command.nested_commands:               
                unpacked_list = ConfigHandler.unpack_command(unpacked_list, nested_command, config_data_part)
        return unpacked_list



    @staticmethod
    def unpack_command(unpacked_list, nested_command, config_data):

        if isinstance(config_data, collections.abc.Mapping):
            
            if len(nested_command.children) == 0:
                if nested_command.command in config_data.keys():
                    # dont print shutdown under management api when server is enabled
                    if config_data[nested_command.command] is not False:
                        config_string = "   " * nested_command.indent + nested_command.command
                        unpacked_list.append(config_string)
                else:
                    # this bydlocode relies on DynamicDeleter object which works for egress_peers dynamic list under traffic-eng nodes
                    if len(nested_command.nested_commands) > 0 and nested_command is not DynamicConfigCommand:
                        config_string = nested_command.command
                        if nested_command.indent:
                            config_string = "   " * nested_command.indent + config_string
                        unpacked_list.append(config_string)
                        for doublensted_command in nested_command.nested_commands:
                            try:
                                config_data[nested_command.deleter.delete_args]
                                unpacked_list = ConfigHandler.unpack_command(unpacked_list, doublensted_command, config_data[nested_command.deleter.delete_args])
                            except KeyError:
                                config_data[nested_command.deleter.delete_args] = []
                                unpacked_list = ConfigHandler.unpack_command(unpacked_list, doublensted_command, config_data[nested_command.deleter.delete_args])
                            except AttributeError:
                                # and here it gets even worse, to handle affinities
                                if isinstance(nested_command.deleter, collections.abc.Mapping):
                                    config_key = list(list(nested_command.deleter.values())[0].keys())[0]
                                    if config_key in config_data.keys():
                                        unpacked_list = ConfigHandler.unpack_command(unpacked_list, doublensted_command, config_data[config_key])

            for command in nested_command.children:
                # do not print cleartext password    
                if command.encrypt: continue
                if isinstance(command, DynamicConfigCommand):
                    if command.command in config_data.keys():
                        if isinstance(config_data[command.command], list):
                            for item in config_data[command.command]:
                                config_list = []
                                ConfigHandler.unpack_parent(config_list, command)
                                config_list.append(str(item))
                                config_string = " ".join(config_list)
                                if command.indent:
                                    config_string = "   " * command.indent + config_string
                                unpacked_list.append(config_string)
                        else:
                            # if argument is None, don't print the line
                            if not config_data[command.command]: continue
                            config_list = []
                            ConfigHandler.unpack_parent(config_list, command)
                            config_list.append(str(config_data[command.command]))
                            if len(command.children) > 0:
                                #print(command.command)
                                for child in command.children:
                                    if isinstance(child, DynamicConfigCommand):
                                        if child.command in config_data.keys():
                                            config_list.append(str(config_data[child.command]))
                                            if len(child.children) > 0:
                                                for child2 in child.children:
                                                    if child2.command in config_data.keys():
                                                        config_list.append(str(config_data[child2.command]))             
                                    else:

                                        config_list.append(child.command)
                                        if len(child.children) > 0:
                                            for child2 in child.children:
                                                if child2.command in config_data.keys():
                                                    config_list.append(str(config_data[child2.command]))
                                                else:
                                                    # yet another dirty hack to correctly display exclusive config parts
                                                    if command.exclusive:
                                                        config_list = config_list[:-1]
 
                            config_string = " ".join(config_list)
                            if command.indent:
                                config_string = "   " * command.indent + config_string
                            unpacked_list.append(config_string)
                    else:
                        if isinstance(command.new_config, DynamicConfigSnippet):
                            if command.new_config.dynamic_list_name in config_data.keys():
                                unpacked_list = ConfigHandler.unpack_list(unpacked_list, nested_command, config_data[command.new_config.dynamic_list_name])
                        else:
                            for config_snippet in command.new_config:
                                if isinstance(config_snippet, DynamicConfigSnippet):
                                    if config_snippet.dynamic_list_name in config_data.keys():
                                        unpacked_list = ConfigHandler.unpack_list(unpacked_list, nested_command, config_data[config_snippet.dynamic_list_name])
                else:
                    if not isinstance(command, DynamicConfigCommand) and len(command.children) == 0:
                        config_list = []
                        ConfigHandler.unpack_parent(config_list, command)
                        config_list.append(command.command)
                        config_string = " ".join(config_list)
                        if command.indent:
                            config_string = "   " * command.indent + config_string
                        unpacked_list.append(config_string)
                        for nested_command in command.nested_commands:
                            # this bydlocode relies on DynamicDeleter object which works for egress_peers_ipv4 dynamic list under traffic-eng nodes
                            if isinstance(command.deleter, DynamicDeleter):
                                unpacked_list = ConfigHandler.unpack_command(unpacked_list, nested_command, config_data[command.deleter.delete_args])
                            # and here it gets even worse...
                            elif isinstance(command.deleter, collections.abc.Mapping) and nested_command.command != "protocol":
                                for k in command.deleter.keys():
                                    section = k
                                for k in command.deleter[section].keys():
                                    section2 = k
                                for k in command.deleter[section][section2].keys():
                                    section3 = k
                                #pprint(nested_command.command)
                                #print(section2)
                                #print(section3)
                                #pprint(config_data)
                                if section2 == "general":
                                    unpacked_list = ConfigHandler.unpack_command(unpacked_list, nested_command, config_data[section2])
                                else:
                                    unpacked_list = ConfigHandler.unpack_command(unpacked_list, nested_command, config_data[section2][section3])
                                #pprint(unpacked_list)
                    else:
                        ConfigHandler.unpack_command(unpacked_list, command, config_data)
        elif isinstance(config_data, list):
            unpacked_list = ConfigHandler.unpack_list(unpacked_list, nested_command, config_data)

        return unpacked_list

    def update_logging_config(self, new_logging_config):
        self.logger.debug(f'Config-handler: Updating logging config')
        logging.config.dictConfig(config=new_logging_config)
        formatter = HostnameFormatter(new_logging_config['formatters']['simple']['format'])
        for handler in logging.getLogger().handlers:
            handler.setFormatter(formatter)


    def return_running_config(self):
        self.logger.debug(f'Config-handler: Returning running-config')
        running_config_lines = []
        for k, v in self.config.items():
            if k not in self.CONFIG_SECTIONS.keys():
                self.logger.error(f'Config-handler: Unknown config-section {k} when returning running-config')
            else:
                config_section = self.CONFIG_SECTIONS[k]
                if len(config_section.children) > 0:
                    config_section = config_section.children[0]
                    # handle 2 levels of child commands e.g. management api
                    if len(config_section.children) > 0:
                        config_section = config_section.children[0]
                    config_list = []
                    ConfigHandler.unpack_parent(config_list, config_section)
                    # static sections e.g. management api
                    if isinstance(v, collections.abc.Mapping):
                        if isinstance (v[config_section.command], collections.abc.Mapping):
                            config_list.append(config_section.command)
                        else:
                            # dynamic sections e.g. router bgp <asn>; if bgp asn not configured, print nothing
                            if not v[config_section.command]: continue
                            config_list.append(str(v[config_section.command]))
                        running_config_lines.append(" ".join(config_list))
                    # handle access lists
                    elif isinstance(v, list):
                        for section in v:
                            if isinstance(section, collections.abc.Mapping):
                                for k2, v2 in section.items():
                                    if not isinstance(v2, list):
                                        if k2 == "description":
                                            running_config_lines.append(f'   {k2} {v2}')
                                        else:
                                            running_config_lines.append("!")
                                            config_list = []
                                            config_list.append(str(config_section.command))
                                            config_list.append(str(v2))
                                            running_config_lines.append(" ".join(config_list))
                                            config_list = []
                                    else:
                                        # handle access lists printing
                                        for nested_command in config_section.parent.nested_commands:
                                            unpacked_list = []
                                            unpacked_list = ConfigHandler.unpack_list(unpacked_list, nested_command, v2)
                                            for line in unpacked_list:
                                                running_config_lines.append(line)
                else:
                    # handle cases with sections of 3 words
                    if config_section.parent.parent:
                        running_config_lines.append(f'{config_section.parent.parent.command} {config_section.parent.command} {config_section.command}')
                    else:
                        running_config_lines.append(f'{config_section.parent.command} {config_section.command}')
                for nested_command in config_section.nested_commands:
                    unpacked_list = []
                    unpacked_list = ConfigHandler.unpack_command(unpacked_list, nested_command, v)
                    for line in unpacked_list:
                        running_config_lines.append(line)
                running_config_lines.append("!")
        return running_config_lines


    def write_startup_config(self):
        self.logger.info(f'Config-handler: Writing startup-config...')
        config_lines = self.return_running_config()
        config_lines.append("end\n")

        try:
            with open(self.startup_config, 'w') as f:
                f.write('\n'.join(config_lines))
                return {'messages': ['Copy completed successfully.']}
        except Exception as e:
            self.logger.error(f'Config-handler: Unable to write startup-config, exception {e.__class__.__name__, e.args}')
            return




default_config = {'bgp': {'asn': None, 'router_id': None, 'neighbors': []},
                 'sampling': {'sampling_interval': 60, 'sampling_database': None, 'adjust_interval': 600, 'adjust_threshold': 10},
                 'telemetry_profiles': [],
                 'telemetry_clients': [],
                 'management': {'http-commands': {'http': {'port': 8080, 'shutdown': False}, 'https': {'port': 8443, 'shutdown': False, 'certificate': None, 'key': None}}},
                 'syslog': {'hosts': []},
                 'users': {'users': []}}
