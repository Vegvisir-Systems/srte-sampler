#!/usr/bin/env python3
from pprint import pprint
import socket
import copy
from config_manager.show_printer import *
from time import time
from datetime import timedelta




def ip_to_string(ip_address_bin):
    return socket.inet_ntop(socket.AF_INET, ip_address_bin)

def string_to_ip(ip_address_str):
    return socket.inet_pton(socket.AF_INET, ip_address_str)

def ip6_to_string(ip_address_bin):
    return socket.inet_ntop(socket.AF_INET6, ip_address_bin)

def string_to_ip6(ip_address_str):
    return socket.inet_pton(socket.AF_INET6, ip_address_str)

class ShowCommand:
    def __init__(self, command):
        self.command = command
        self.parent = None
        self.children = []
        self.responder = None
        self.query = None
        self.printer = None
        self.cli_context_help = "Not available"
        self.cli_allowed_args = "<N/A>"

    def add_child(self, child):
        child.parent = self
        self.children.append(child)

    def set_responder(self, responder):
        self.responder = responder

    def set_query(self, query):
        self.query = query

    def set_printer(self, printer):
        self.printer = printer

    #children need to be sorted to that regular show command are before dynamic commands for correct handling
    def sort_children(self):
        sorted_children = []
        for item in self.children:
            if not isinstance(item, DynamicShowCommand):
                sorted_children.append(item)
        for item in self.children:
            if isinstance(item, DynamicShowCommand):
                sorted_children.append(item)
        self.children = sorted_children

    def set_cli_context_help(self, cli_context_help):
        self.cli_context_help = cli_context_help

    def set_cli_allowed_args(self, cli_allowed_args):
        self.cli_allowed_args = cli_allowed_args

class DynamicShowCommand(ShowCommand):
    def __init__(self, command):
        super().__init__(command)

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
        "ip": set_var_ip,
        "ipv4": set_var_ipv4,
        "ipv6": set_var_ipv6,
        "iso": set_var_iso,
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
            return

        self.var_type = var_type
        func = self.SET_VARS[var_type]
        func(self, args)


# show version

show_version = ShowCommand("version")
show_version.set_query("version")
show_version.set_responder("system")
show_version.set_printer(print_show_version)
show_version.set_cli_context_help("Software version")

# show threads

show_threads = ShowCommand("threads")
show_threads.set_query("threads")
show_threads.set_responder("system")
show_threads.set_printer(print_show_threads)
show_threads.set_cli_context_help("Threads status")

# show running-config

show_running_config = ShowCommand("running-config")
show_running_config.set_query("running_config")
show_running_config.set_responder("system")
show_running_config.set_printer(print_show_running_config)
show_running_config.set_cli_context_help("System running configuration")

# show startup-config // for NAPALM - for now returns same as running-config

show_startup_config = ShowCommand("startup-config")
show_startup_config.set_query("running_config")
show_startup_config.set_responder("system")
show_startup_config.set_printer(print_show_running_config)
show_startup_config.set_cli_context_help("System startup configuration")

# show running-config raw // hack for CLI

show_running_config_raw = ShowCommand("raw")
show_running_config.add_child(show_running_config_raw)
show_running_config_raw.set_query("running_config_raw")
show_running_config_raw.set_responder("system")
show_running_config_raw.set_printer(print_show_running_config)

# show tech-support
# available only from CLI

show_tech_support = ShowCommand("tech-support")
show_tech_support.set_query("tech_support")
show_tech_support.set_responder("system")
show_tech_support.set_cli_context_help("System configuration details and diagnostics information")

show_active = ShowCommand("active")
show_active.set_query("active")
show_active.set_responder("system")
show_active.set_cli_context_help("Show the current running-config for this sub mode")


# show logging 
# available only from CLI

show_logging = ShowCommand("logging")
show_logging.set_query("logging")
show_logging.set_responder("system")
show_logging.set_cli_context_help("Show system logs")

# show logging recent
# available only from CLI

show_logging_recent = ShowCommand("recent")
show_logging.add_child(show_logging_recent)
show_logging_recent.set_query("logging_recent")
show_logging_recent.set_responder("system")
show_logging_recent.set_cli_context_help("Show last 50 lines of system logs")

# show logging follow
# available only from CLI

show_logging_follow = ShowCommand("follow")
show_logging.add_child(show_logging_follow)
show_logging_follow.set_query("logging_follow")
show_logging_follow.set_responder("system")
show_logging_follow.set_cli_context_help("Show system logs in interactive mode")

# show bgp summary

show_bgp = ShowCommand("bgp")
show_bgp.set_cli_context_help("BGP information")
show_bgp_summary = ShowCommand("summary")
show_bgp.add_child(show_bgp_summary)
show_bgp_summary.set_responder("bgp_server")
show_bgp_summary.set_query("bgp_summary")
show_bgp_summary.set_printer(print_show_bgp_summary)
show_bgp_summary.set_cli_context_help("Summarized BGP information")

# show bgp neighbors

show_bgp_neighbors = ShowCommand("neighbors")
show_bgp.add_child(show_bgp_neighbors)
show_bgp_neighbors.set_responder("bgp_server")
show_bgp_neighbors.set_query("bgp_neighbors")
show_bgp_neighbors.set_printer(print_show_bgp_neighbors)
show_bgp_neighbors.set_cli_context_help("BGP neighbor information")

# show bgp neighbors <ipv4|ipv6>

show_bgp_neighbors_specific_neighbor = DynamicShowCommand("specific_neighbor")
show_bgp_neighbors.add_child(show_bgp_neighbors_specific_neighbor)
show_bgp_neighbors_specific_neighbor.set_variable_command(var_type="ip", args=None)
show_bgp_neighbors_specific_neighbor.set_responder("bgp_server")
show_bgp_neighbors_specific_neighbor.set_query("bgp_neighbors")
show_bgp_neighbors_specific_neighbor.set_printer(print_show_bgp_neighbors)
show_bgp_neighbors_specific_neighbor.set_cli_context_help("BGP specific neighbor information")
show_bgp_neighbors_specific_neighbor.set_cli_allowed_args("<ipv4|ipv6>")

# show bgp link-state

show_bgp_link_state = ShowCommand("link-state")
show_bgp.add_child(show_bgp_link_state)
show_bgp_link_state.set_responder("bgp_server")
show_bgp_link_state.set_query("bgp_link_state")
show_bgp_link_state.set_printer(print_show_bgp_link_state)
show_bgp_link_state.set_cli_context_help("BGP link-state information")

# show bgp link-state <nlri>

show_bgp_link_state_specific_nlri = DynamicShowCommand("specific_nlri")
show_bgp_link_state.add_child(show_bgp_link_state_specific_nlri)
show_bgp_link_state_specific_nlri.set_variable_command(var_type="generic_string", args=(1, 255))
show_bgp_link_state_specific_nlri.set_responder("bgp_server")
show_bgp_link_state_specific_nlri.set_query("bgp_link_state")
show_bgp_link_state_specific_nlri.set_printer(print_show_bgp_link_state_detail)
show_bgp_link_state_specific_nlri.set_cli_context_help("BGP link-state information for specific NLRI")
show_bgp_link_state_specific_nlri.set_cli_allowed_args("<LS NLRI>")

# show bgp link-state detail

show_bgp_link_state_detail = ShowCommand("detail")
show_bgp_link_state.add_child(show_bgp_link_state_detail)
show_bgp_link_state_detail.set_responder("bgp_server")
show_bgp_link_state_detail.set_query("bgp_link_state_detail")
show_bgp_link_state_detail.set_printer(print_show_bgp_link_state_detail)
show_bgp_link_state_detail.set_cli_context_help("Detailed BGP link-state information")

# show bgp link-state <nlri> detail

show_bgp_link_state_specific_nlri_detail = ShowCommand("detail")
show_bgp_link_state_specific_nlri.add_child(show_bgp_link_state_specific_nlri_detail)
show_bgp_link_state_specific_nlri_detail.set_responder("bgp_server")
show_bgp_link_state_specific_nlri_detail.set_query("bgp_link_state_detail")
show_bgp_link_state_specific_nlri_detail.set_printer(print_show_bgp_link_state_detail)
show_bgp_link_state_specific_nlri_detail.set_cli_context_help("Detailed BGP link-state information for specific NLRI")


# show bgp neighbors <ipv4|ipv6> link-state received-routes

show_bgp_neighbors_specific_neighbor_link_state = ShowCommand("link-state")
show_bgp_neighbors_specific_neighbor_link_state.set_cli_context_help("BGP link-state information for neighbor")
show_bgp_neighbors_specific_neighbor.add_child(show_bgp_neighbors_specific_neighbor_link_state)
show_bgp_neighbors_specific_neighbor_link_state_received_routes = ShowCommand("received-routes")
show_bgp_neighbors_specific_neighbor_link_state.add_child(show_bgp_neighbors_specific_neighbor_link_state_received_routes)
show_bgp_neighbors_specific_neighbor_link_state_received_routes.set_responder("bgp_server")
show_bgp_neighbors_specific_neighbor_link_state_received_routes.set_query("bgp_neighbors_link_state_received_routes")
show_bgp_neighbors_specific_neighbor_link_state_received_routes.set_printer(print_show_bgp_link_state)
show_bgp_neighbors_specific_neighbor_link_state_received_routes.set_cli_context_help("BGP link-state routes received from neighbor")

show_bgp_link_state.sort_children()

# show bgp internal

show_bgp_internal = ShowCommand("internal")
show_bgp.add_child(show_bgp_internal)
show_bgp_internal.set_responder("bgp_server")
show_bgp_internal.set_query("bgp_internal")
show_bgp_internal.set_printer(print_bgp_internal)
show_bgp_internal.set_cli_context_help("BGP internal information")


# show management api http

show_management = ShowCommand("management")
show_management.set_cli_context_help("Management services information")
show_management_api = ShowCommand("api")
show_management_api.set_cli_context_help("API information")
show_management.add_child(show_management_api)
show_management_api_http = ShowCommand("http")
show_management_api_http.set_cli_context_help("HTTP API information")
show_management_api.add_child(show_management_api_http)
show_management_api_http.set_responder("mgmt_server")
show_management_api_http.set_query("management_api_http")
show_management_api_http.set_printer(print_show_management_api_http)

# show management api https

show_management_api_https = ShowCommand("https")
show_management_api_https.set_cli_context_help("HTTPS API information")
show_management_api.add_child(show_management_api_https)
show_management_api_https.set_responder("mgmt_server")
show_management_api_https.set_query("management_api_https")
show_management_api_https.set_printer(print_show_management_api_https)

show_management_api.sort_children()

# show management syslog

show_management_syslog = ShowCommand("syslog")
show_management_syslog.set_cli_context_help("Syslog configuration and status")
show_management.add_child(show_management_syslog)
show_management_syslog.set_responder("system")
show_management_syslog.set_query("management_syslog")
show_management_syslog.set_printer(print_show_management_syslog)


# show sampling summary

show_sampling = ShowCommand("sampling")
show_sampling.set_cli_context_help("Sampling information")
show_sampling_summary = ShowCommand("summary")
show_sampling.add_child(show_sampling_summary)
show_sampling_summary.set_responder("sampling_server")
show_sampling_summary.set_query("sampling_summary")
show_sampling_summary.set_printer(print_show_sampling_summary)
show_sampling_summary.set_cli_context_help("Summarized sampling clients information")

# show sampling clients

show_sampling_clients = ShowCommand("clients")
show_sampling.add_child(show_sampling_clients)
show_sampling_clients.set_responder("sampling_server")
show_sampling_clients.set_query("sampling_clients")
show_sampling_clients.set_printer(print_show_sampling_clients)
show_sampling_clients.set_cli_context_help("Sampling clients detailed information")

# show sampling clients <ipv4|ipv6>

show_sampling_clients_specific_client = DynamicShowCommand("specific_client")
show_sampling_clients.add_child(show_sampling_clients_specific_client)
show_sampling_clients_specific_client.set_variable_command(var_type="ip", args=None)
show_sampling_clients_specific_client.set_responder("sampling_server")
show_sampling_clients_specific_client.set_query("sampling_clients")
show_sampling_clients_specific_client.set_printer(print_show_sampling_clients)
show_sampling_clients_specific_client.set_cli_context_help("Specific sampling client information")
show_sampling_clients_specific_client.set_cli_allowed_args("<ipv4|ipv6>")

# show sampling policies

show_sampling_policies = ShowCommand("policies")
show_sampling.add_child(show_sampling_policies)
show_sampling_policies.set_responder("sampling_server")
show_sampling_policies.set_query("sampling_policies")
show_sampling_policies.set_printer(print_show_sampling_policies)
show_sampling_policies.set_cli_context_help("Sampling policies information")

# show sampling policies <policy_key>

show_sampling_policies_specific_policy = DynamicShowCommand("specific_nlri")
show_sampling_policies.add_child(show_sampling_policies_specific_policy)
show_sampling_policies_specific_policy.set_variable_command(var_type="generic_string", args=(1, 255))
show_sampling_policies_specific_policy.set_responder("sampling_server")
show_sampling_policies_specific_policy.set_query("sampling_policies")
show_sampling_policies_specific_policy.set_printer(print_show_sampling_policies_detail)
show_sampling_policies_specific_policy.set_cli_context_help("Sampling policies information for specific policy")
show_sampling_policies_specific_policy.set_cli_allowed_args("<POLICY KEY>")

# show sampling policies detail

show_sampling_policies_detail = ShowCommand("detail")
show_sampling_policies.add_child(show_sampling_policies_detail)
show_sampling_policies_detail.set_responder("sampling_server")
show_sampling_policies_detail.set_query("sampling_policies_detail")
show_sampling_policies_detail.set_printer(print_show_sampling_policies_detail)
show_sampling_policies_detail.set_cli_context_help("Detailed sampling policies information")

# show sampling policies <policy_key> detail

show_sampling_policies_specific_policy_detail = ShowCommand("detail")
show_sampling_policies_specific_policy.add_child(show_sampling_policies_specific_policy_detail)
show_sampling_policies_specific_policy_detail.set_responder("sampling_server")
show_sampling_policies_specific_policy_detail.set_query("sampling_policies_detail")
show_sampling_policies_specific_policy_detail.set_printer(print_show_sampling_policies_detail)
show_sampling_policies_specific_policy_detail.set_cli_context_help("Detailed sampling policies information for specific policy")

show_sampling_policies.sort_children()

# show sampling internal

show_sampling_internal = ShowCommand("internal")
show_sampling.add_child(show_sampling_internal)
show_sampling_internal.set_responder("sampling_server")
show_sampling_internal.set_query("sampling_internal")
show_sampling_internal.set_printer(print_sampling_internal)
show_sampling_internal.set_cli_context_help("Sampling server internal information")



global_show_commands = [show_version, show_threads, show_running_config, show_startup_config, show_tech_support, show_logging, show_bgp, show_management, show_sampling]

class ShowHandler:
    def __init__(self, command_server, config_handler, bgp_server, mgmt_server, sampling_server, logger):
        self.start_time = int(time())
        self.command_server = command_server
        self.config_handler = config_handler
        self.bgp_server = bgp_server
        self.mgmt_server = mgmt_server
        self.sampling_server = sampling_server
        self.logger = logger

        self.SHOW_COMMAND_RESPONDERS = {
            "bgp_server": self.bgp_server,
            "mgmt_server": self.mgmt_server,
            "sampling_server": self.sampling_server,
            "system": self
        }


    def show_version(self):
        self.logger.debug(f'Show handler: Returning show version')
        version = {}
        version["mfg_name"] = "Vegvisir Systems"
        version["model_name"] = "SRTE Bandwidth Sampler"
        version["hostname"] = socket.gethostname()
        version["start_time"] = self.start_time
        version["uptime"] = str(timedelta(seconds=int(time()) - self.start_time))
        version["version"] = "0.1"
        version["build_date"] = "2026-02-24"
        return version
    
    def show_threads(self):
        self.logger.debug(f'Show handler: Returning threads')
        return self.command_server.return_all_keepalives()
    
    def show_management_syslog(self):
        self.logger.debug(f'Show handler: Returning syslog config')
        return self.command_server.return_syslog_config()

    @staticmethod
    def pack_config(line, packed_config, doublepacked_config, triplepacked_config, quadrapacked_config):
        # rewrite this shame using recursion
        line = line[3:]
        if line[0] != " ":
            if not packed_config:
                packed_config = {'cmds': {}}
            packed_config['cmds'][line] = doublepacked_config
            doublepacked_config = None
        else:
            line = line[3:]
            if line[0] != " ":
                if not doublepacked_config:
                    doublepacked_config = {'cmds': {}}
                doublepacked_config['cmds'][line] = triplepacked_config
                triplepacked_config = None
            else:
                line = line[3:]
                if line[0] != " ":
                    if not triplepacked_config:
                        triplepacked_config = {'cmds': {}}
                    triplepacked_config['cmds'][line] = quadrapacked_config
                    quadrapacked_config = None
                else:
                    line = line[3:]
                    if line[0] != " ":
                        if not quadrapacked_config:
                            quadrapacked_config = {'cmds': {}}
                        quadrapacked_config['cmds'][line] = None

        return packed_config, doublepacked_config, triplepacked_config, quadrapacked_config

    def show_running_config(self):
        self.logger.debug(f'Show handler: Returning running-config')
        config_lines = self.config_handler.return_running_config()
        running_config = {'cmds': {}}
        config_lines.reverse()
        packed_config = None
        doublepacked_config = None
        triplepacked_config = None
        quadrapacked_config = None
        for line in config_lines:
            if line.strip() != "!":
                if line[0:3] != "   ":
                    running_config['cmds'][line] = packed_config
                    packed_config = None
                else:
                    packed_config, doublepacked_config, triplepacked_config, quadrapacked_config = self.pack_config(line, packed_config, doublepacked_config, triplepacked_config, quadrapacked_config)

        return running_config
    
    def show_running_config_raw(self):
        return self.config_handler.return_running_config()

    def show_tech_support(self):
        return "show tech-support not available from API"

    def show_active(self):
        return "show active not available from API"    

    def show_logging(self):
        return "show logging not available from API" 
    
    def show_logging_recent(self):
        return "show logging recent not available from API" 
    
    def show_logging_follow(self):
        return "show logging follow not available from API" 
        
    def return_show_command(self, responder, query, printer, response_format="json", command=None):
        self.logger.debug(f'Show handler: Returning show command response query "{query}" responder "{responder}"')
        try:
            if responder not in self.SHOW_COMMAND_RESPONDERS.keys():
                return
            if command:
                if response_format == "text":
                    if not printer:
                        return f'% Printer not available for query "{query}"'
                    return printer(self.SHOW_COMMAND_RESPONDERS[responder].show_command(query, command))
                return self.SHOW_COMMAND_RESPONDERS[responder].show_command(query, command)
            if response_format == "text":
                if not printer:
                    return f'% Printer not available for query "{query}"'
                return printer(self.SHOW_COMMAND_RESPONDERS[responder].show_command(query))
            return self.SHOW_COMMAND_RESPONDERS[responder].show_command(query)
        except Exception as e:
            self.logger.warning(f'Show handler: Failed to response to query "{query}" responder "{responder}" - exception {e.__class__.__name__, e.args}')
            return f'% Got exception when running query "{query}"'

    def parse_show_command(self, parsed_line, response_format="json"):
        self.logger.debug(f'Show handler: Parsing line "{parsed_line}"')
        parsed_line = parsed_line[1:]
        previous_command = None
        previous_arg = None
        while len(parsed_line) > 0:
            command = parsed_line.pop(0)
            if not previous_command:
                for show_command in global_show_commands:
                    #print(show_command.command)
                    if show_command.command == command:
                        if len(parsed_line) == 0:
                            return self.return_show_command(show_command.responder, show_command.query, show_command.printer, response_format)
                        previous_command = show_command
                        # this line is for the case when second command is dynamic
                        # is not strictly required with current set of commands
                        # added for consistency with clear handler
                        command = parsed_line.pop(0)
                        break
            if not previous_command:
                return
            

            for show_command in previous_command.children:
                if isinstance(show_command, DynamicShowCommand):
                    if show_command.var_type not in show_command.CHECK_VARS.keys():
                        self.logger.error(f'Show handler: Incorrect var type {show_command.var_type}')
                        return
                    func = show_command.CHECK_VARS[show_command.var_type]
                    command = func(show_command, command)
                    
                    if command is False:
                        return
                    if len(parsed_line) == 0:
                        return self.return_show_command(show_command.responder, show_command.query, show_command.printer, response_format, command)
                    previous_command = show_command
                    previous_arg = command
                    break
                if show_command.command == command:
                    if len(parsed_line) == 0:
                        if previous_arg:
                            return self.return_show_command(show_command.responder, show_command.query, show_command.printer, response_format, previous_arg)
                        return self.return_show_command(show_command.responder, show_command.query, show_command.printer, response_format)
                    previous_command = show_command
                    break

        return


    def show_command(self, query, command=None):
        return self.get_response(query, command)
    
    RESPONDERS = {
        "version": show_version,
        "threads": show_threads,
        "management_syslog": show_management_syslog,
        "running_config": show_running_config,
        "running_config_raw": show_running_config_raw,
        "tech_support": show_tech_support,
        "active": show_active,
        "logging": show_logging,
        "logging_recent": show_logging_recent,
        "logging_follow": show_logging_follow
    }

    def get_response(self, query, command=None):
        self.logger.debug(f'Show handler: Getting response to query "{query}"')
        if query not in self.RESPONDERS.keys():
            return
        if command:
            return self.RESPONDERS[query](self, command)
        return self.RESPONDERS[query](self)