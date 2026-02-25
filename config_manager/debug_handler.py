#!/usr/bin/env python3
from pprint import pprint
import socket


def ip_to_string(ip_address_bin):
    return socket.inet_ntop(socket.AF_INET, ip_address_bin)

def string_to_ip(ip_address_str):
    return socket.inet_pton(socket.AF_INET, ip_address_str)

def ip6_to_string(ip_address_bin):
    return socket.inet_ntop(socket.AF_INET6, ip_address_bin)

def string_to_ip6(ip_address_str):
    return socket.inet_pton(socket.AF_INET6, ip_address_str)

class DebugCommand:
    def __init__(self, command):
        self.command = command
        self.parent = None
        self.children = []
        self.responder = None
        self.query = None
        self.cli_context_help = "Not available"
        self.cli_allowed_args = "<N/A>"

    def add_child(self, child):
        child.parent = self
        self.children.append(child)

    def set_responder(self, responder):
        self.responder = responder

    def set_query(self, query):
        self.query = query

    #children need to be sorted to that regular debug command are before dynamic commands for correct handling
    def sort_children(self):
        sorted_children = []
        for item in self.children:
            if not isinstance(item, DynamicDebugCommand):
                sorted_children.append(item)
        for item in self.children:
            if isinstance(item, DynamicDebugCommand):
                sorted_children.append(item)
        self.children = sorted_children

    def set_cli_context_help(self, cli_context_help):
        self.cli_context_help = cli_context_help

    def set_cli_allowed_args(self, cli_allowed_args):
        self.cli_allowed_args = cli_allowed_args


class DynamicDebugCommand(DebugCommand):
    def __init__(self, command):
        super().__init__(command)

    def set_var_ip_wildecard(self, args):
        pass

    def set_var_ip(self, args):
        pass

    def set_var_ipv4(self, args):
        pass

    def set_var_ipv6(self, args):
        pass

    def set_var_iso(self, args):
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

    SET_VARS = {
        "ip_wildecard": set_var_ip_wildecard,
        "ip": set_var_ip,
        "ipv4": set_var_ipv4,
        "ipv6": set_var_ipv6,
        "iso": set_var_iso,
        "dec_integer": set_var_dec_integer,
        "hex_integer": set_var_hex_integer,
        "generic_string": set_var_generic_string,
        "specific_string": set_var_specific_string
    }

    def check_var_ip_wildecard(self, command):
        if command == "*":
            return command
        try:
            string_to_ip(command)
        except OSError:
            try:
                string_to_ip6(command)
            except OSError:
                return False
        return command

    def check_var_ip(self, command):
        try:
            string_to_ip(command)
        except OSError:
            try:
                string_to_ip6(command)
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
            string_to_ip6(command)
        except OSError:
            return False
        return command

    def check_var_iso(self, command):
        return command

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
        "ip_wildecard": check_var_ip_wildecard,
        "ip": check_var_ip,
        "ipv4": check_var_ipv4,
        "ipv6": check_var_ipv6,
        "iso": check_var_iso,
        "dec_integer": check_var_dec_integer,
        "hex_integer": check_var_hex_integer,
        "generic_string": check_var_generic_string,
        "specific_string": check_var_specific_string
    }

    def set_variable_command(self, var_type, args=None):
        if var_type not in self.SET_VARS.keys():
            #print(f'Unknown variable type {var_type}')
            return

        self.var_type = var_type
        func = self.SET_VARS[var_type]
        func(self, args)


# debug bgp server

debug_bgp = DebugCommand("bgp")
debug_bgp.set_cli_context_help("BGP debugs")
debug_bgp_server = DebugCommand("server")
debug_bgp.add_child(debug_bgp_server)
debug_bgp_server.set_responder("bgp_server")
debug_bgp_server.set_query("bgp_server")
debug_bgp_server.set_cli_context_help("BGP server debug")

# debug bgp neighbors <ipv4|ipv6|*>

debug_bgp_neighbors = DebugCommand("neighbors")
debug_bgp_neighbors.set_cli_context_help("BGP neighbors debug")
debug_bgp.add_child(debug_bgp_neighbors)
debug_bgp_neighbors_specific_neighbor = DynamicDebugCommand("specific_neighbor")
debug_bgp_neighbors.add_child(debug_bgp_neighbors_specific_neighbor)
debug_bgp_neighbors_specific_neighbor.set_variable_command(var_type="ip_wildecard", args=None)
debug_bgp_neighbors_specific_neighbor.set_responder("bgp_server")
debug_bgp_neighbors_specific_neighbor.set_query("bgp_neighbors")
debug_bgp_neighbors_specific_neighbor.set_cli_context_help("BGP neighbors debug")
debug_bgp_neighbors_specific_neighbor.set_cli_allowed_args("<ipv4|ipv6|*>")


# debug management command-server

debug_management = DebugCommand("management")
debug_management.set_cli_context_help("Management debugs")
debug_management_command_server = DebugCommand("command-server")
debug_management.add_child(debug_management_command_server)
debug_management_command_server.set_responder("command_server")
debug_management_command_server.set_query("command_server")
debug_management_command_server.set_cli_context_help("Command server debug")

# debug management config-handler

debug_management_config_handler = DebugCommand("config-handler")
debug_management.add_child(debug_management_config_handler)
debug_management_config_handler.set_responder("command_server")
debug_management_config_handler.set_query("config_handler")
debug_management_config_handler.set_cli_context_help("Config handler debug")

# debug management api

debug_management_api = DebugCommand("api")
debug_management.add_child(debug_management_api)
debug_management_api.set_responder("mgmt_server")
debug_management_api.set_query("api")
debug_management_api.set_cli_context_help("API server debug")

# debug sampling server

debug_sampling = DebugCommand("sampling")
debug_sampling.set_cli_context_help("Sampling debugs")
debug_sampling_server = DebugCommand("server")
debug_sampling.add_child(debug_sampling_server)
debug_sampling_server.set_responder("sampling_server")
debug_sampling_server.set_query("bgp_server")
debug_sampling_server.set_cli_context_help("Sampling server debug")

# debug sampling clients <ipv4|ipv6|*>


debug_sampling_clients = DebugCommand("clients")
debug_sampling_clients.set_cli_context_help("Sampling clients debug")
debug_sampling.add_child(debug_sampling_clients)
debug_sampling_clients_specific_client = DynamicDebugCommand("specific_client")
debug_sampling_clients.add_child(debug_sampling_clients_specific_client)
debug_sampling_clients_specific_client.set_variable_command(var_type="ip_wildecard", args=None)
debug_sampling_clients_specific_client.set_responder("sampling_server")
debug_sampling_clients_specific_client.set_query("sampling_clients")
debug_sampling_clients_specific_client.set_cli_context_help("Sampling clients debug")
debug_sampling_clients_specific_client.set_cli_allowed_args("<ipv4|ipv6|*>")

# debug all

debug_all = DebugCommand("all")
debug_all.set_responder("debug_handler")
debug_all.set_query("debug_all")
debug_all.set_cli_context_help("Debug all - use if you like to live dangerously")


global_debug_commands = [debug_bgp, debug_management, debug_sampling, debug_all]


class DebugHandler:
    def __init__(self, command_server, bgp_server, mgmt_server, sampling_server, logger):
        self.command_server = command_server
        self.bgp_server = bgp_server
        self.mgmt_server = mgmt_server
        self.sampling_server = sampling_server
        self.logger = logger

        self.DEBUG_COMMAND_RESPONDERS = {
            "command_server": self.command_server,
            "bgp_server": self.bgp_server,
            "mgmt_server": self.mgmt_server,
            "sampling_server": self.sampling_server,
            "debug_handler": self
        }
        self.EXISTING_DEBUGS = [
            {"responder": "bgp_server",
            "query": "bgp_server",
            "command": None},
            {"responder": "bgp_server",
             "query": "bgp_neighbors",
             "command": "*"},
            {"responder": "command_server",
             "query": "command_server",
             "command": None},
            {"responder": "command_server",
             "query": "config_handler",
             "command": None},
            {"responder": "mgmt_server",
             "query": "api",
             "command": None},
            {"responder": "sampling_server",
             "query": "sampling_server",
             "command": None},
            {"responder": "sampling_server",
             "query": "sampling_clients",
             "command": "*"}
        ]
    
    def return_debug_command(self, responder, query, command=None, undebug=False):
        self.logger.debug(f'Debug handler: Returning debug command response query "{query}" responder "{responder}"')
        if responder not in self.DEBUG_COMMAND_RESPONDERS.keys():
            return
        if command:
            return self.DEBUG_COMMAND_RESPONDERS[responder].debug_command(query, command=command, undebug=undebug)
        return self.DEBUG_COMMAND_RESPONDERS[responder].debug_command(query, command=None, undebug=undebug)

    def debug_command(self, query, command=None, undebug=False):
        if query != "debug_all": return
        result_list = []
        for existing_debug in self.EXISTING_DEBUGS:
            result = self.return_debug_command(existing_debug["responder"], existing_debug["query"], existing_debug["command"], undebug)
            result_list.append(result)
        return result_list
    
    def parse_debug_command(self, parsed_line, undebug=False):
        self.logger.debug(f'Debug handler: Parsing line "{parsed_line}"')
        parsed_line = parsed_line[1:]
        previous_command = None
        previous_arg = None
        while len(parsed_line) > 0:
            command = parsed_line.pop(0)
            if not previous_command:
                for debug_command in global_debug_commands:
                    if debug_command.command == command:
                        if len(parsed_line) == 0:
                            return self.return_debug_command(debug_command.responder, debug_command.query, command=None, undebug=undebug)
                        previous_command = debug_command
                        command = parsed_line.pop(0)
            if not previous_command:
                return

            for debug_command in previous_command.children:            
                if isinstance(debug_command, DynamicDebugCommand):
                    if debug_command.var_type not in debug_command.CHECK_VARS.keys():
                        self.logger.error(f'Clear handler: Incorrect var type {debug_command.var_type}')
                        return
                    func = debug_command.CHECK_VARS[debug_command.var_type]
                    command = func(debug_command, command)
                  
                    if command is False:
                        return
                    if len(parsed_line) == 0:
                        return self.return_debug_command(debug_command.responder, debug_command.query, command=command, undebug=undebug)
                    previous_command = debug_command
                    previous_arg = command
                    break
                if debug_command.command == command:
                    if len(parsed_line) == 0:
                        if previous_arg:
                            return self.return_debug_command(debug_command.responder, debug_command.query, command=previous_arg, undebug=undebug)
                        return self.return_debug_command(debug_command.responder, debug_command.query, command=None, undebug=undebug)
                    previous_command = debug_command
                    break

        return