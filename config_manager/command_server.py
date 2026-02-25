#!/usr/bin/env python3


from pprint import pprint
from eventlet import GreenPool, listen, connect, greenthread, sleep
from eventlet.queue import Queue
from pympler import asizeof
import msgpack
import logging
import logging.config
from time import time
from datetime import timedelta
import copy
from deepdiff import DeepDiff
import socket
from time import perf_counter
import subprocess
import os
import gzip
import shutil
from concurrent_log_handler import ConcurrentRotatingFileHandler


from .show_handler import ShowHandler
from .clear_handler import ClearHandler
from .debug_handler import DebugHandler

class HostnameFormatter(logging.Formatter):
    def format(self, record):
        record.hostname = socket.gethostname()
        return super().format(record)

class CompressedConcurrentRotatingFileHandler(ConcurrentRotatingFileHandler):
    def doRollover(self):
        # Keep existing rotation behavior
        super().doRollover()

        # Compress rotated backups
        for i in range(1, self.backupCount + 1):
            rotated_file = f"{self.baseFilename}.{i}"
            if os.path.exists(rotated_file) and not rotated_file.endswith(".gz"):
                gz_file = rotated_file + ".gz"
                with open(rotated_file, "rb") as f_in, gzip.open(gz_file, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
                os.remove(rotated_file)

class CommandServer:
    def __init__(self, config_handler, bgp_server, mgmt_server, sampling_server, default_logging_config):
        self.api_interfaces = []
        self.config_handler = config_handler
        self.bgp_server = bgp_server
        self.mgmt_server = mgmt_server
        self.sampling_server = sampling_server
        self.logger = logging.getLogger("command_server")
        self.show_handler = ShowHandler(self, self.config_handler, self.bgp_server, self.mgmt_server, self.sampling_server, self.logger)
        self.clear_handler = ClearHandler(self.config_handler, self.bgp_server, self.mgmt_server, self.sampling_server, self.logger)
        self.debug_handler = DebugHandler(self, self.bgp_server, self.mgmt_server, self.sampling_server, self.logger)
        self.process_commands_keepalive = 0
        self.config_update_keepalive = 0
        self.get_sampling_request_keepalive = 0
        self.all_threads_keepalives = {
            "command_server_keepalive": "Never",
            "command_server_status": "FAIL",
            "get_sampling_request_keepalive": "Never",
            "get_sampling_request_status": "N/A",
            "syslog_config_update_keepalive": "Never",
            "syslog_config_update_status": "N/A",
            "mgmt_config_update_keepalive": "Never",
            "mgmt_config_update_status": "FAIL",
            "bgp_config_update_keepalive": "Never",
            "bgp_config_update_status": "FAIL",
            "bgp_signal_receiver_keepalive": "Never",
            "bgp_signal_receiver_status": "FAIL",
            "bgp_ls_loc_rib_keepalive": "Never",
            "bgp_ls_loc_rib_status": "FAIL",
            "sampling_config_update_keepalive": "Never",
            "sampling_config_update_status": "FAIL",
            "sampling_gnmi_streaming_keepalive": "Never",
            "sampling_gnmi_streaming_status": "FAIL",
            "sampling_calculate_bandwidth_keepalive": "Never",
            "sampling_calculate_bandwidth_status": "FAIL",
            "sampling_cleanup_old_policies_keepalive": "Never",
            "sampling_cleanup_old_policies_status": "FAIL"
        }     
        self.config_updates = Queue()
        self.CONFIG_SERVERS = {
            "bgp": self.bgp_server,
            "management": self.mgmt_server,
            "sampling": self.sampling_server,
            "telemetry_profiles": self.sampling_server,
            "telemetry_clients": self.sampling_server,
            "syslog": self,
            "users": self,
        }
        self.default_logging_config = default_logging_config
        self.syslog_config = config_handler.config["syslog"]
        self.users_config = config_handler.config["users"]["users"]
        self.old_srte_distinguisher = None
        self.old_bgp_router_id = None
        self.old_pcep_init_delay = None


    def run(self):
        self.logger.debug(f'Command-server: Creating users')
        for user_config in self.users_config:
            if "password" not in user_config.keys():
                self.logger.debug(f'Command-server: User {user_config["username"]} has no password configured, skipping')
                continue
            subprocess.run(["/usr/sbin/useradd", "-m", "-s", "/bin/bash", user_config["username"]])
            subprocess.run(["/usr/sbin/usermod", "-p", user_config["password"], user_config["username"]])
            self.logger.debug(f'Command-server: Created user {user_config["username"]}')

        self.logger.debug(f'Command-server: Starting threads')
        self.pool = GreenPool()
        self.threads = []
        self.threads.append(self.pool.spawn(self.process_commands))
        self.threads.append(self.pool.spawn(self.update_config))
        self.threads.append(self.pool.spawn(self.get_sampling_server_requests))
        self.threads.append(self.pool.spawn(self.collect_keepalives))
        self.pool.waitall()


    def call_show_handler(self, command, response_format="json"):
        self.logger.debug(f'Command-server: Sending command "{command}" to show handler')
        command = command.split()
        if len(command) == 1:
            return        
        return self.show_handler.parse_show_command(command, response_format)

    def call_clear_handler(self, command, response_format="json"):
        self.logger.debug(f'Command-server: Sending command "{command}" to clear handler')
        command = command.split()
        if len(command) == 1:
            return        
        return self.clear_handler.parse_clear_command(command)

    def call_debug_handler(self, command, response_format="json"):
        self.logger.debug(f'Command-server: Sending command "{command}" to debug handler')
        command = command.split()
        if len(command) == 1:
            return        
        return self.debug_handler.parse_debug_command(command, undebug=False)

    def call_undebug_handler(self, command, response_format="json"):
        self.logger.debug(f'Command-server: Sending command "{command}" to debug handler')
        command = command.split()
        if len(command) == 1:
            return        
        return self.debug_handler.parse_debug_command(command, undebug=True)
        
    def call_write_handler(self, command, response_format="json"):
        self.logger.debug(f'Command-server: Writing startup config')
        command = command.split()
        if len(command) > 1:
            return
        return self.config_handler.write_startup_config()


    COMMAND_HANDLERS = {
        "show": call_show_handler,
        "clear": call_clear_handler,
        "debug": call_debug_handler,
        "undebug": call_undebug_handler,
        "write": call_write_handler
    }


    def type_changes(self, config_changes):
        changes_dict = {}
        for change_path, change_value in config_changes.items():
            change_path = change_path[4:].replace('[', '').split(']')[:-1]
            change_server = change_path[0].strip("'")
            change_path_processed = []
            for item in change_path[1:]:
                item = item.strip("'")
                change_path_processed.append(item)
            if change_server not in changes_dict.keys():
                changes_dict[change_server] = []
                changes_dict[change_server].append((change_path_processed, change_value))
            else:
                changes_dict[change_server].append((change_path_processed, change_value))
        for change_server, changes_list in changes_dict.items():
            if change_server in self.CONFIG_SERVERS.keys():
                self.CONFIG_SERVERS[change_server].add_config_changes("type_changes", change_server, changes_list, self.config_handler.config)


    def values_changed(self, config_changes):
        changes_dict = {}
        for change_path, change_value in config_changes.items():
            change_path = change_path[4:].replace('[', '').split(']')[:-1]
            change_server = change_path[0].strip("'")
            change_path_processed = []
            for item in change_path[1:]:
                item = item.strip("'")
                change_path_processed.append(item)
            if change_server not in changes_dict.keys():
                changes_dict[change_server] = []
                changes_dict[change_server].append((change_path_processed, change_value))
            else:
                changes_dict[change_server].append((change_path_processed, change_value))
        for change_server, changes_list in changes_dict.items():
            if change_server in self.CONFIG_SERVERS.keys():
                self.CONFIG_SERVERS[change_server].add_config_changes("values_changed", change_server, changes_list, self.config_handler.config)


    def dictionary_item_added(self, config_changes):
        changes_dict = {}
        for change_path in config_changes:
            change_path = change_path[4:].replace('[', '').split(']')[:-1]
            change_server = change_path[0].strip("'")
            change_path_processed = []
            for item in change_path[1:]:
                item = item.strip("'")
                change_path_processed.append(item)
            if change_server not in changes_dict.keys():
                changes_dict[change_server] = []
                changes_dict[change_server].append((change_path_processed, None))
            else:
                changes_dict[change_server].append((change_path_processed, None))
        for change_server, changes_list in changes_dict.items():
            if change_server in self.CONFIG_SERVERS.keys():
                self.CONFIG_SERVERS[change_server].add_config_changes("dictionary_item_added", change_server, changes_list, self.config_handler.config)


    def dictionary_item_removed(self, config_changes):
        changes_dict = {}
        for change_path in config_changes:
            change_path = change_path[4:].replace('[', '').split(']')[:-1]
            change_server = change_path[0].strip("'")
            change_path_processed = []
            for item in change_path[1:]:
                item = item.strip("'")
                change_path_processed.append(item)
            if change_server not in changes_dict.keys():
                changes_dict[change_server] = []
                changes_dict[change_server].append((change_path_processed, None))
            else:
                changes_dict[change_server].append((change_path_processed, None))
        for change_server, changes_list in changes_dict.items():
            if change_server in self.CONFIG_SERVERS.keys():
                self.CONFIG_SERVERS[change_server].add_config_changes("dictionary_item_removed", change_server, changes_list, self.config_handler.config)


    def iterable_item_added(self, config_changes):
        changes_dict = {}
        for change_path, change_value in config_changes.items():
            change_path = change_path[4:].replace('[', '').split(']')[:-1]
            change_server = change_path[0].strip("'")
            change_path_processed = []
            for item in change_path[1:]:
                item = item.strip("'")
                change_path_processed.append(item)
            if change_server not in changes_dict.keys():
                changes_dict[change_server] = []
                changes_dict[change_server].append((change_path_processed, change_value))
            else:
                changes_dict[change_server].append((change_path_processed, change_value))
        for change_server, changes_list in changes_dict.items():
            if change_server in self.CONFIG_SERVERS.keys():
                self.CONFIG_SERVERS[change_server].add_config_changes("iterable_item_added", change_server, changes_list, self.config_handler.config)


    def iterable_item_removed(self, config_changes):
        changes_dict = {}
        for change_path, change_value in config_changes.items():
            change_path = change_path[4:].replace('[', '').split(']')[:-1]
            change_server = change_path[0].strip("'")
            change_path_processed = []
            for item in change_path[1:]:
                item = item.strip("'")
                change_path_processed.append(item)
            if change_server not in changes_dict.keys():
                changes_dict[change_server] = []
                changes_dict[change_server].append((change_path_processed, change_value))
            else:
                changes_dict[change_server].append((change_path_processed, change_value))
        for change_server, changes_list in changes_dict.items():
            if change_server in self.CONFIG_SERVERS.keys():
                self.CONFIG_SERVERS[change_server].add_config_changes("iterable_item_removed", change_server, changes_list, self.config_handler.config)


    CHANGE_TYPES = {
        "type_changes": type_changes,
        "values_changed": values_changed,
        "dictionary_item_added": dictionary_item_added,
        "dictionary_item_removed": dictionary_item_removed,
        "iterable_item_added": iterable_item_added,
        "iterable_item_removed": iterable_item_removed
    }

    def process_config_update(self, config_update):
        self.logger.debug(f'Command-server: Processing config update {config_update}')
        #print("Config change:")
        #print(config_update)
        #pprint(self.config_handler.config)

        for k, v in config_update.items():
            if k in self.CHANGE_TYPES:
                func = self.CHANGE_TYPES[k]
                func(self, v)


    def process_commands(self):
        while True:
            sleep(0.1)
            if int(time()) > self.process_commands_keepalive:
                self.process_commands_keepalive = int(time())
            init_time = round(time()*1000)
            while True:
                if round(time()*1000) - init_time > 200: 
                    if config_attempt:
                        config_diff = DeepDiff(old_config, self.config_handler.config, ignore_order=True)
                        if config_diff:
                            self.process_config_update(config_diff)
                    break
                api_name, query = self.mgmt_server.get_query()
                if not query: break

                self.logger.debug(f'Command-server: Received query {query} from API {api_name}')
                response, commands, response_format = query

                command_num = 0
                config_mode = False
                config_attempt = False
                old_config = copy.deepcopy(self.config_handler.config)
                failed = False
                result = []
                sync_enabled = False
                if len(commands) > 10000:
                    result = []
                    response["error"] = {}
                    response["error"]["code"] = -32602
                    response["error"]["message"] = (f"Too many commands send in one request: {len(commands)} received; maximum 10000 allowed. Please use multiple requests")
                    self.logger.debug(f'Command-server: Sending response {response} to API {api_name}')
                    self.mgmt_server.enqueue_answer(api_name, response)
                    break
                for command in commands:
                    original_command = command
                    if response_format == "text":
                        if command == "show startup-config" or command == "show running-config":
                            command = "show running-config raw"
                    command_num += 1
                    if not isinstance(command, str):
                        if config_attempt:
                            # if command failed - undo all config changes made in this request so far
                            self.config_handler.swap_config(old_config)
                        response["error"] = {}
                        response["error"]["code"] = -32602
                        response["error"]["message"] = (f"Command {command_num} out of {len(commands)} '{command}' failed")
                        self.logger.debug(f'Command-server: Sending response {response} to API {api_name}')
                        self.mgmt_server.enqueue_answer(api_name, response)
                        break
                    if command.split()[0] in self.COMMAND_HANDLERS.keys():
                        func = self.COMMAND_HANDLERS[command.split()[0]]
                        command_result = func(self, command, response_format)
                        if command_result:
                            #result.append(command_result)

                            # experimental code for NAPALM integration
                            if response_format == "text":
                                if command == "show running-config raw":
                                    if original_command == "show startup-config":
                                        raw_command_result = {'output': "! Command: show startup-config\n"}
                                    else:
                                        raw_command_result = {'output': "! Command: show running-config\n"}
                                    config_lines = '\n'.join(command_result)
                                    raw_command_result['output'] = raw_command_result['output'] + config_lines
                                    result.append(raw_command_result)
                                else:
                                    raw_command_result = {'output': ""}
                                    raw_command_result['output'] = raw_command_result['output'] + command_result
                                    result.append(raw_command_result)
                            else:
                                result.append(command_result)
                        else:
                            failed = True
                            if failed:
                                if config_attempt:
                                    # if command failed - undo all config changes made in this request so far
                                    self.config_handler.swap_config(old_config)
                                response["error"] = {}
                                response["error"]["code"] = -32602
                                response["error"]["message"] = (f"Command {command_num} out of {len(commands)} '{command}' failed")
                                self.logger.debug(f'Command-server: Sending response {response} to API {api_name}')
                                self.mgmt_server.enqueue_answer(api_name, response)
                                break
                        continue
                    if command == "configure":
                        config_mode = True
                        self.logger.debug(f'Command-server: Entering config mode')
                        self.config_handler.init_config()
                        config_attempt = True
                        result.append({})
                        continue
                    if config_mode:
                        if command == "end":
                            self.logger.debug(f'Command-server: Exiting config mode')
                            config_mode = False
                            if config_attempt:
                                config_diff = DeepDiff(old_config, self.config_handler.config, ignore_order=True)
                                if config_diff:
                                    self.process_config_update(config_diff)
                            config_attempt = False
                            result.append({})
                            continue
                        else:
                            self.logger.debug(f'Command-server: Applying config command "{command}"')
                            command_result = self.config_handler.apply_command_without_diff(command)
                            if command_result:
                                result.append({})
                            else:
                                if config_attempt:
                                    self.config_handler.swap_config(old_config)
                                response["error"] = {}
                                response["error"]["code"] = -32602
                                response["error"]["message"] = (f"Command {command_num} out of {len(commands)} '{command}' failed")
                                self.logger.debug(f'Command-server: Sending response {response} to API {api_name}')
                                self.mgmt_server.enqueue_answer(api_name, response)
                                break
                            continue
                        
                    failed = True
                    if failed:
                        if config_attempt:
                            # if command failed - undo all config changes made in this request so far
                            self.config_handler.swap_config(old_config)
                        response["error"] = {}
                        response["error"]["code"] = -32602
                        response["error"]["message"] = (f"Command {command_num} out of {len(commands)} '{command}' failed")
                        self.logger.debug(f'Command-server: Sending response {response} to API {api_name}')
                        self.mgmt_server.enqueue_answer(api_name, response)
                        break


                if not failed:
                    if config_attempt:
                        config_diff = DeepDiff(old_config, self.config_handler.config, ignore_order=True)
                        if config_diff:
                            self.process_config_update(config_diff)
                    if response_format == "binary":
                        result = msgpack.packb(result, use_bin_type=True).hex()


                    if asizeof.asizeof(result) > 314572800:
                        result = []
                        response["error"] = {}
                        response["error"]["code"] = -32602
                        response["error"]["message"] = (f"Command {command_num} out of {len(commands)} '{command}' failed - response size over 300MB not allowed")
                        self.logger.debug(f'Command-server: Sending response {response} to API {api_name}')
                        self.mgmt_server.enqueue_answer(api_name, response)
                        break
                    else:
                        response["result"] = result
                        self.mgmt_server.enqueue_answer(api_name, response)
                        self.logger.debug(f'Command-server: Sending response {response} to API {api_name}')
                        break



    def update_policy(self, policy):
        self.bgp_server.update_policy(policy)

    def delete_policy(self, policy):
        self.bgp_server.delete_policy(policy)


    SAMPLING_REQUESTS = {
        "update_policy": update_policy,
        "delete_policy": delete_policy
    }


    def get_sampling_server_requests(self):
        while True:
            sleep(0.1)
            if int(time()) > self.get_sampling_request_keepalive:
                self.get_sampling_request_keepalive = int(time())
            init_time = round(time()*1000)
            while True:
                if round(time()*1000) - init_time > 200: break
                request = self.sampling_server.get_sampling_to_bgp_query()
                if not request: break
                request_type, args = request
                self.logger.debug(f'Command-server: Got sampling server request type {request_type}')
                try:
                    func = self.SAMPLING_REQUESTS[request_type]
                    func(self, args)
                except KeyError:
                    self.logger.error(f'Command-server: Invalid sampling server request type {request_type}')


    def collect_keepalives(self):
        while True:
            sleep(1)
            self.logger.debug(f'Command-server: Collecting threads keepalives')
            try:
                if self.process_commands_keepalive:
                    self.all_threads_keepalives["command_server_keepalive"] = int(time()) - self.process_commands_keepalive
                    if self.all_threads_keepalives["command_server_keepalive"] < 10:
                        self.all_threads_keepalives["command_server_status"] = "OK"
                    else:
                        if self.all_threads_keepalives["command_server_status"] == "OK":
                            self.logger.critical(f'Command-server: Command server failed, unable to process new commands')
                        self.all_threads_keepalives["command_server_status"] = "FAIL"
                else:
                    self.all_threads_keepalives["command_server_keepalive"] = "Never"
                    self.all_threads_keepalives["command_server_status"] = "FAIL"
                if self.get_sampling_request_keepalive:
                    self.all_threads_keepalives["get_sampling_request_keepalive"] = int(time()) - self.get_sampling_request_keepalive
                    if self.all_threads_keepalives["get_sampling_request_keepalive"] < 10:
                        self.all_threads_keepalives["get_sampling_request_status"] = "OK"
                    else:
                        if self.all_threads_keepalives["get_sampling_request_status"] == "OK":
                            self.logger.critical(f'Command-server: Get sampling request process failed, unable to convert sampling data to BGP-LS')
                        self.all_threads_keepalives["get_sampling_request_status"] = "FAIL"
                else:
                    self.all_threads_keepalives["get_sampling_request_keepalive"] = "Never"
                    self.all_threads_keepalives["get_sampling_request_status"] = "FAIL"
                if self.config_update_keepalive:
                    self.all_threads_keepalives["syslog_config_update_keepalive"] = int(time()) - self.config_update_keepalive
                    if self.all_threads_keepalives["syslog_config_update_keepalive"] < 10:
                        self.all_threads_keepalives["syslog_config_update_status"] = "OK"
                    else:
                        if self.all_threads_keepalives["syslog_config_update_status"] == "OK":
                            self.logger.critical(f'Command-server: Syslog config updater failed, unable to update syslog config')
                        self.all_threads_keepalives["syslog_config_update_status"] = "FAIL"
                else:
                    self.all_threads_keepalives["syslog_config_update_keepalive"] = "Never"
                    self.all_threads_keepalives["syslog_config_update_status"] = "FAIL"
                # MGMT server / API handler
                mgmt_server_keepalives = self.mgmt_server.return_keepalives()
                if mgmt_server_keepalives["config_update_keepalive"]:
                    self.all_threads_keepalives["mgmt_config_update_keepalive"] = int(time()) - mgmt_server_keepalives["config_update_keepalive"]
                    if self.all_threads_keepalives["mgmt_config_update_keepalive"] < 10:
                        self.all_threads_keepalives["mgmt_config_update_status"] = "OK"
                    else:
                        if self.all_threads_keepalives["mgmt_config_update_status"] == "OK":
                            self.logger.critical(f'Command-server: Management server config updater failed, unable to update management config')
                        self.all_threads_keepalives["mgmt_config_update_status"] = "FAIL"
                else:
                    self.all_threads_keepalives["mgmt_config_update_keepalive"] = "Never"
                    self.all_threads_keepalives["mgmt_config_update_status"] = "FAIL"
                # BGP server
                bgp_server_keepalives = self.bgp_server.return_keepalives()
                if bgp_server_keepalives["config_update_keepalive"]:
                    self.all_threads_keepalives["bgp_config_update_keepalive"] = int(time()) - bgp_server_keepalives["config_update_keepalive"]
                    if self.all_threads_keepalives["bgp_config_update_keepalive"] < 10:
                        self.all_threads_keepalives["bgp_config_update_status"] = "OK"
                    else:
                        if self.all_threads_keepalives["bgp_config_update_status"] == "OK":
                            self.logger.critical(f'Command-server: BGP server config updater failed, unable to update BGP config')
                        self.all_threads_keepalives["bgp_config_update_status"] = "FAIL"
                else:
                    self.all_threads_keepalives["bgp_config_update_keepalive"] = "Never"
                    self.all_threads_keepalives["bgp_config_update_status"] = "FAIL"     

                if bgp_server_keepalives["signal_receiver_keepalive"]:
                    self.all_threads_keepalives["bgp_signal_receiver_keepalive"] = int(time()) - bgp_server_keepalives["signal_receiver_keepalive"]
                    if self.all_threads_keepalives["bgp_signal_receiver_keepalive"] < 10:
                        self.all_threads_keepalives["bgp_signal_receiver_status"] = "OK"
                    else:
                        if self.all_threads_keepalives["bgp_signal_receiver_status"] == "OK":
                            self.logger.critical(f'Command-server: BGP server signal receiver failed, BGP unable to receive signals')
                        self.all_threads_keepalives["bgp_signal_receiver_status"] = "FAIL"
                else:
                    self.all_threads_keepalives["bgp_signal_receiver_keepalive"] = "Never"
                    self.all_threads_keepalives["bgp_signal_receiver_status"] = "FAIL"

                if bgp_server_keepalives["link-state"]:
                    self.all_threads_keepalives["bgp_ls_loc_rib_keepalive"] = int(time()) - bgp_server_keepalives["link-state"]
                    if self.all_threads_keepalives["bgp_ls_loc_rib_keepalive"] < 10:
                        self.all_threads_keepalives["bgp_ls_loc_rib_status"] = "OK"
                    else:
                        if self.all_threads_keepalives["bgp_ls_loc_rib_status"] == "OK":
                            self.logger.critical(f'Command-server: BGP server LS LocRib failed, BGP unable to process LS routes')
                        self.all_threads_keepalives["bgp_ls_loc_rib_status"] = "FAIL"
                else:
                    self.all_threads_keepalives["bgp_ls_loc_rib_keepalive"] = "Never"
                    self.all_threads_keepalives["bgp_ls_loc_rib_status"] = "FAIL"
    
                # Sampling server
                sampling_server_keepalives = self.sampling_server.return_keepalives()
                if sampling_server_keepalives["config_update_keepalive"]:
                    self.all_threads_keepalives["sampling_config_update_keepalive"] = int(time()) - sampling_server_keepalives["config_update_keepalive"]
                    if self.all_threads_keepalives["sampling_config_update_keepalive"] < 10:
                        self.all_threads_keepalives["sampling_config_update_status"] = "OK"
                    else:
                        if self.all_threads_keepalives["sampling_config_update_status"] == "OK":
                            self.logger.critical(f'Command-server: Sampling server config updater failed, unable to update config')
                        self.all_threads_keepalives["sampling_config_update_status"] = "FAIL"
                else:
                    self.all_threads_keepalives["sampling_config_update_keepalive"] = "Never"
                    self.all_threads_keepalives["sampling_config_update_status"] = "FAIL"

                if sampling_server_keepalives["gnmi_streaming_keepalive"]:
                    self.all_threads_keepalives["sampling_gnmi_streaming_keepalive"] = int(time()) - sampling_server_keepalives["gnmi_streaming_keepalive"]
                    if self.all_threads_keepalives["sampling_gnmi_streaming_keepalive"] < 10:
                        self.all_threads_keepalives["sampling_gnmi_streaming_status"] = "OK"
                    else:
                        if self.all_threads_keepalives["sampling_gnmi_streaming_status"] == "OK":
                            self.logger.critical(f'Command-server: Sampling server GNMI streamer failed, unable to sample policies')
                        self.all_threads_keepalives["sampling_gnmi_streaming_status"] = "FAIL"
                else:
                    self.all_threads_keepalives["sampling_gnmi_streaming_keepalive"] = "Never"
                    self.all_threads_keepalives["sampling_gnmi_streaming_status"] = "FAIL"

                if sampling_server_keepalives["calculate_bandwidth_keepalive"]:
                    self.all_threads_keepalives["sampling_calculate_bandwidth_keepalive"] = int(time()) - sampling_server_keepalives["calculate_bandwidth_keepalive"]
                    if self.all_threads_keepalives["sampling_calculate_bandwidth_keepalive"] < 10:
                        self.all_threads_keepalives["sampling_calculate_bandwidth_status"] = "OK"
                    else:
                        if self.all_threads_keepalives["sampling_calculate_bandwidth_status"] == "OK":
                            self.logger.critical(f'Command-server: Sampling server bandwidth calculator failed, unable to calculate sampled policy bandwidth')
                        self.all_threads_keepalives["sampling_calculate_bandwidth_status"] = "FAIL"
                else:
                    self.all_threads_keepalives["sampling_calculate_bandwidth_keepalive"] = "Never"
                    self.all_threads_keepalives["sampling_calculate_bandwidth_status"] = "FAIL"

                if sampling_server_keepalives["cleanup_old_policies_keepalive"]:
                    self.all_threads_keepalives["sampling_cleanup_old_policies_keepalive"] = int(time()) - sampling_server_keepalives["cleanup_old_policies_keepalive"]
                    if self.all_threads_keepalives["sampling_cleanup_old_policies_keepalive"] < 10:
                        self.all_threads_keepalives["sampling_cleanup_old_policies_status"] = "OK"
                    else:
                        if self.all_threads_keepalives["sampling_cleanup_old_policies_status"] == "OK":
                            self.logger.critical(f'Command-server: Sampling server old policy cleaner failed, unable to cleanup old policies')
                        self.all_threads_keepalives["sampling_cleanup_old_policies_status"] = "FAIL"
                else:
                    self.all_threads_keepalives["sampling_cleanup_old_policies_keepalive"] = "Never"
                    self.all_threads_keepalives["sampling_cleanup_old_policies_status"] = "FAIL"

            except Exception as e:
                self.logger.warning(f'Command-server: failed to check all threads keepalives, exception {e.__class__.__name__, e.args}')                       


    def return_all_keepalives(self):
        self.logger.debug(f'Command-server: Returning threads keepalives')
        return self.all_threads_keepalives


    def return_syslog_config(self):
        self.logger.debug(f'Command-server: Returning syslog config')
        syslog_config = {"configured_syslog_hosts": []}
        for host in self.syslog_config["hosts"]:
            host_config = {}
            host_config["remote_ip"] = host["remote_ip"]
            host_config["protocol"] = host.get("protocol", None)
            host_config["port"] = host.get("port", None)
            if host_config["protocol"] and host_config["port"]:
                host_config["active"] = True
            else:
                host_config["active"] = False
            syslog_config["configured_syslog_hosts"].append(host_config)
        return syslog_config


    def add_config_changes(self, change_type, change_server, changes_list, running_config=None):
        for change_item in changes_list:
            self.logger.debug(f'Command-server: Queuing config change {change_type}, {change_item[0]}, {change_item[1]}')
            self.config_updates.put((change_type, change_server, change_item[0], change_item[1], running_config))


    def update_config(self):
        while True:
            sleep(2)
            self.config_update_keepalive = int(time())
            if not self.config_updates.qsize(): continue
            init_time = round(time()*1000)
            while self.config_updates.qsize():
                self.logger.debug(f'Command-server: Fetching config updates')
                if round(time()*1000) - init_time > 200: break
                change_type, change_server, change_path_processed, change_values, running_config = self.config_updates.get()
                try:
                    if change_server == "syslog":
                        self.syslog_config = running_config["syslog"]
                        new_logging_config = copy.deepcopy(self.default_logging_config)
                        for host in self.syslog_config["hosts"]:
                            remote_ip = host["remote_ip"]
                            protocol = host.get("protocol", None)
                            port = host.get("port", None)
                            if protocol and port:
                                new_logging_config["handlers"][f'remote_host_{remote_ip}'] = {}
                                new_logging_config["handlers"][f'remote_host_{remote_ip}']["class"] = "logging.handlers.SysLogHandler"
                                new_logging_config["handlers"][f'remote_host_{remote_ip}']["formatter"] = "simple"
                                new_logging_config["handlers"][f'remote_host_{remote_ip}']["address"] = (remote_ip, port)
                                if protocol == "tcp":
                                    new_logging_config["handlers"][f'remote_host_{remote_ip}']["socktype"] = 1
                                new_logging_config["loggers"]["root"]["handlers"].append(f'remote_host_{remote_ip}')
                        logging.config.dictConfig(config=new_logging_config)
                        formatter = HostnameFormatter(new_logging_config['formatters']['simple']['format'])
                        for handler in logging.getLogger().handlers:
                            handler.setFormatter(formatter)
                        self.bgp_server.update_logging_config(new_logging_config)
                        self.mgmt_server.update_logging_config(new_logging_config)
                        self.sampling_server.update_logging_config(new_logging_config)
                        self.config_handler.update_logging_config(new_logging_config)
                    if change_server == "users":
                        self.users_config = running_config["users"]["users"]
                        user_index = int(change_path_processed[1])
                        if change_type == "iterable_item_added":
                            self.logger.debug(f'Command-server: Added user {change_values["username"]}')
                            # don't create user without a password
                            pass
                        elif change_type == "iterable_item_removed":
                            self.logger.debug(f'Command-server: Deleting user {change_values["username"]}')
                            # delete user
                            subprocess.run(["/usr/sbin/userdel", change_values["username"]])
                        elif change_type == "dictionary_item_added":
                            self.logger.debug(f'Command-server: Creating user {self.users_config[user_index]["username"]}')
                            # create user, set password
                            subprocess.run(["/usr/sbin/useradd", "-m", "-s", "/bin/bash", self.users_config[user_index]["username"]])
                            subprocess.run(["/usr/sbin/usermod", "-p", self.users_config[user_index]["password"], self.users_config[user_index]["username"]])
                        elif change_type == "dictionary_item_removed":
                            # delete user
                            self.logger.debug(f'Command-server: Deleting user {self.users_config[user_index]["username"]}')
                            subprocess.run(["/usr/sbin/userdel", self.users_config[user_index]["username"]])
                        elif change_type == "values_changed":
                            # change password
                            self.logger.debug(f'Command-server: Changing password for user {self.users_config[user_index]["username"]}')
                            subprocess.run(["/usr/sbin/usermod", "-p", self.users_config[user_index]["password"], self.users_config[user_index]["username"]])
                except:
                    self.logger.exception(f'Command-server: Unable to process config change for {change_server}, {change_type}, {change_path_processed}, {change_values}')


    def debug_command_server(self, command=None, undebug=False):
        if undebug:
            self.logger.warning(f'Command-server: Disabling debug for Command server')
            self.logger.setLevel(logging.INFO)
            return {'warnings': ['Disabled debugging for Command server']}
        self.logger.warning(f'Command-server: Enabling debug for Command server')
        self.logger.setLevel(logging.DEBUG)
        return {'warnings': ['Enabled debugging for Command server']}
    
    def debug_config_handler(self, command=None, undebug=False):
        if undebug:
            self.logger.warning(f'Command-server: Disabling debug for Config handler')
            self.config_handler.logger.setLevel(logging.INFO)
            return {'warnings': ['Disabled debugging for Config handler']}
        self.logger.warning(f'Command-server: Enabling debug for Config handler')
        self.config_handler.logger.setLevel(logging.DEBUG)
        return {'warnings': ['Enabled debugging for Config handler']}

    DEBUG_RESPONDERS = {
        "command_server": debug_command_server,
        "config_handler": debug_config_handler
    }

    def debug_command(self, query, command=None, undebug=False):
        self.logger.debug(f'Command-server: Received debug command query {query}, arguments {command}')
        if query not in self.DEBUG_RESPONDERS.keys(): return
        return self.DEBUG_RESPONDERS[query](self, command, undebug=undebug)