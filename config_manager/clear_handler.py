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

class ClearCommand:
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

    #children need to be sorted to that regular clear command are before dynamic commands for correct handling
    def sort_children(self):
        sorted_children = []
        for item in self.children:
            if not isinstance(item, DynamicClearCommand):
                sorted_children.append(item)
        for item in self.children:
            if isinstance(item, DynamicClearCommand):
                sorted_children.append(item)
        self.children = sorted_children

    def set_cli_context_help(self, cli_context_help):
        self.cli_context_help = cli_context_help

    def set_cli_allowed_args(self, cli_allowed_args):
        self.cli_allowed_args = cli_allowed_args


class DynamicClearCommand(ClearCommand):
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



# clear bgp <ipv4|ipv6|*>

clear_bgp = ClearCommand("bgp")
clear_bgp.set_cli_context_help("Clear BGP peering sessions")
clear_bgp_neighbors = DynamicClearCommand("neighbors")
clear_bgp.add_child(clear_bgp_neighbors)
clear_bgp_neighbors.set_variable_command(var_type="ip_wildecard", args=None)
clear_bgp_neighbors.set_responder("bgp_server")
clear_bgp_neighbors.set_query("bgp_neighbors")
clear_bgp_neighbors.set_cli_context_help("Clear BGP peering sessions/soft clear by default")
clear_bgp_neighbors.set_cli_allowed_args("<ipv4|ipv6|*>")

# clear bgp <ipv4|ipv6|*> in

clear_bgp_neighbors_in = ClearCommand("in")
clear_bgp_neighbors.add_child(clear_bgp_neighbors_in)
clear_bgp_neighbors_in.set_responder("bgp_server")
clear_bgp_neighbors_in.set_query("bgp_neighbors_in")
clear_bgp_neighbors_in.set_cli_context_help("Send route refresh to peer")

# clear bgp <ipv4|ipv6|*> out

clear_bgp_neighbors_out = ClearCommand("out")
clear_bgp_neighbors.add_child(clear_bgp_neighbors_out)
clear_bgp_neighbors_out.set_responder("bgp_server")
clear_bgp_neighbors_out.set_query("bgp_neighbors_out")
clear_bgp_neighbors_out.set_cli_context_help("Readvertise all routes to peer")

# clear bgp <ipv4|ipv6|*> hard

clear_bgp_neighbors_hard = ClearCommand("hard")
clear_bgp_neighbors.add_child(clear_bgp_neighbors_hard)
clear_bgp_neighbors_hard.set_responder("bgp_server")
clear_bgp_neighbors_hard.set_query("bgp_neighbors_hard")
clear_bgp_neighbors_hard.set_cli_context_help("Reset BGP session")

clear_bgp_neighbors.sort_children()




global_clear_commands = [clear_bgp]




class ClearHandler:
    def __init__(self, config_handler, bgp_server, mgmt_server, sampling_server, logger):
        self.config_handler = config_handler
        self.bgp_server = bgp_server
        self.mgmt_server = mgmt_server
        self.sampling_server = sampling_server
        self.logger = logger

        self.CLEAR_COMMAND_RESPONDERS = {
            "bgp_server": self.bgp_server,
            "mgmt_server": self.mgmt_server,
            "sampling_server": self.sampling_server
        }

    
    def return_clear_command(self, responder, query, command=None):
        self.logger.debug(f'Clear handler: Returning clear command response query "{query}" responder "{responder}"')
        if responder not in self.CLEAR_COMMAND_RESPONDERS.keys():
            return
        if command:
            return self.CLEAR_COMMAND_RESPONDERS[responder].clear_command(query, command)
        return self.CLEAR_COMMAND_RESPONDERS[responder].clear_command(query)

    def parse_clear_command(self, parsed_line):
        self.logger.debug(f'Clear handler: Parsing line "{parsed_line}"')
        parsed_line = parsed_line[1:]
        previous_command = None
        previous_arg = None
        while len(parsed_line) > 0:
            command = parsed_line.pop(0)
            if not previous_command:
                for clear_command in global_clear_commands:
                    if clear_command.command == command:
                        if len(parsed_line) == 0:
                            return self.return_clear_command(clear_command.responder, clear_command.query)
                        previous_command = clear_command
                        command = parsed_line.pop(0)
            if not previous_command:
                return

            for clear_command in previous_command.children:            
                if isinstance(clear_command, DynamicClearCommand):
                    if clear_command.var_type not in clear_command.CHECK_VARS.keys():
                        self.logger.error(f'Clear handler: Incorrect var type {clear_command.var_type}')
                        return
                    func = clear_command.CHECK_VARS[clear_command.var_type]
                    command = func(clear_command, command)
                  
                    if command is False:
                        return
                    if len(parsed_line) == 0:
                        return self.return_clear_command(clear_command.responder, clear_command.query, command)
                    previous_command = clear_command
                    previous_arg = command
                    break
                if clear_command.command == command:
                    if len(parsed_line) == 0:
                        if previous_arg:
                            return self.return_clear_command(clear_command.responder, clear_command.query, previous_arg)
                        return self.return_clear_command(clear_command.responder, clear_command.query)
                    previous_command = clear_command
                    break

        return

