#!/usr/bin/env python3

import json
from jsonrpclib import Server
from pprint import pprint
import socket
import termios, fcntl, sys, os
from config_manager.show_handler import *
from config_manager.clear_handler import *
from config_manager.debug_handler import *
from config_manager.config_handler import *
import pydoc
import subprocess
import msgpack
import shlex

import ssl
_create_unverified_https_context = ssl._create_unverified_context
ssl._create_default_https_context = _create_unverified_https_context



switch = Server("http://127.0.0.1:48777/command-api")


allowed_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`~!@#$%^&*()-_=+[]{}|,.<>\"'/\\;: "


def read_single_keypress():
    """Waits for a single keypress on stdin.

    This is a silly function to call if you need to do it a lot because it has
    to store stdin's current setup, setup stdin for reading single keystrokes
    then read the single keystroke then revert stdin back after reading the
    keystroke.

    Returns a tuple of characters of the key that was pressed - on Linux, 
    pressing keys like up arrow results in a sequence of characters. Returns 
    ('\x03',) on KeyboardInterrupt which can happen when a signal gets
    handled.

    """
    fd = sys.stdin.fileno()
    # save old state
    flags_save = fcntl.fcntl(fd, fcntl.F_GETFL)
    attrs_save = termios.tcgetattr(fd)
    # make raw - the way to do this comes from the termios(3) man page.
    attrs = list(attrs_save) # copy the stored version to update
    # iflag
    attrs[0] &= ~(termios.IGNBRK | termios.BRKINT | termios.PARMRK
                  | termios.ISTRIP | termios.INLCR | termios. IGNCR
                  | termios.ICRNL | termios.IXON )
    # oflag
    attrs[1] &= ~termios.OPOST
    # cflag
    attrs[2] &= ~(termios.CSIZE | termios. PARENB)
    attrs[2] |= termios.CS8
    # lflag
    attrs[3] &= ~(termios.ECHONL | termios.ECHO | termios.ICANON
                  | termios.ISIG | termios.IEXTEN)
    termios.tcsetattr(fd, termios.TCSANOW, attrs)
    # turn off non-blocking
    fcntl.fcntl(fd, fcntl.F_SETFL, flags_save & ~os.O_NONBLOCK)
    # read a single keystroke
    ret = []
    try:
        ret.append(sys.stdin.read(1)) # returns a single character
        fcntl.fcntl(fd, fcntl.F_SETFL, flags_save | os.O_NONBLOCK)
        c = sys.stdin.read(1) # returns a single character
        while len(c) > 0:
            ret.append(c)
            c = sys.stdin.read(1)
    except KeyboardInterrupt:
        ret.append('\x03')
    finally:
        # restore old state
        termios.tcsetattr(fd, termios.TCSAFLUSH, attrs_save)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags_save)
    return tuple(ret)

def custom_join(lst):
    result = []
    in_quotes = False
    current_phrase = []

    for word in lst:
        if '"' in word:
            if not in_quotes:
                current_phrase.append(word)
                in_quotes = True
            else:
                current_phrase.append(word)
                in_quotes = False
                result.append(" ".join(current_phrase))
                current_phrase = []
        else:
            if in_quotes:
                current_phrase.append(word)
            else:
                if " " in word:
                    result.append(f'"{word}"')
                else:
                    result.append(word)

    return result

def longest_common_prefix(strings):
    if not strings:
        return ""
    min_length = min(len(s) for s in strings)
    for i in range(min_length):
        if len(set(s[i] for s in strings)) > 1:
            return strings[0][:i]
    return strings[0][:min_length]


class CliShell:
    def __init__(self):
        self.prompt = f'{socket.gethostname()}#'
        self.current_level = "exec"
        try:
            self.terminal_length = os.get_terminal_size()[1]
        except OSError:
            self.terminal_length = 24
        self.exit = False
        self.command_history_exec = []
        self.historic_command_number_exec = 1
        self.command_history_config = []
        self.historic_command_number_config = 1
        self.api_connection = Server("http://127.0.0.1:48777/command-api")
        self.level_prefix = []



    def call_configure_handler(self, input_symbols, just_complete=False, get_helper=False):
        if len(input_symbols) > 0:
            if input_symbols[0] == "t":
                self.current_level = "config"
                self.prompt = f'{socket.gethostname()}(config)#'
                return True, None
            return False, "% Invalid input"
        self.current_level = "config"
        self.prompt = f'{socket.gethostname()}(config)#'
        return True, None


    SHOW_TECH_COMMANDS = {
        "show version": show_version,
        "show running-config raw": show_running_config,
        "show logging": show_logging,
        "show threads": show_threads,
        "show bgp summary": show_bgp_summary,
        "show bgp neighbors": show_bgp_neighbors,
        "show bgp internal": show_bgp_internal,
        "show bgp link-state": show_bgp_link_state,
        "show bgp link-state detail": show_bgp_link_state_detail,
        "show management api http": show_management_api_http,
        "show management api https": show_management_api_https,
        "show management syslog": show_management_syslog,
        "show sampling summary": show_sampling_summary,
        "show sampling clients": show_sampling_clients,
        "show sampling policies": show_sampling_policies,
        "show sampling policies detail": show_sampling_policies_detail,
        "show sampling internal": show_sampling_internal
    }

    def call_config_handler(self, first_command, input_symbols, just_complete, get_helper=False, delete_config=False):
        input_symbols.insert(0, first_command)
        if len(input_symbols) == 0:
            return False, "% Incomplete command"
        if self.current_level == "exec":
            return False, "% Invalid input"
        if self.current_level == "config":
            available_commands = global_commands
        else:
            available_commands = self.current_level.nested_commands
            for global_command in global_commands:
                skip_command = False
                for already_available_command in available_commands:
                    if global_command.command == already_available_command.command:
                        skip_command = True
                        break
                if skip_command: continue
                if global_command not in available_commands:
                    available_commands.append(global_command)
        current_command = None
        completed_command_string = []
        while len(input_symbols) > 0:
            remaining_commands = available_commands.copy()
            symbol_num = 0
            dynamic_command = None
            command = input_symbols.pop(0)
            for symbol in command:
                for available_command in available_commands:
                    if isinstance(available_command, DynamicConfigCommand):
                        dynamic_command = available_command
                        if available_command in remaining_commands:
                            remaining_commands.remove(available_command)
                            for potential_cli_helper in remaining_commands:
                                if potential_cli_helper.is_cli_helper():
                                    #print(potential_cli_helper.command)
                                    remaining_commands.remove(potential_cli_helper)
                        #if len(available_command.cli_helpers) > 0:
                        #   for cli_helper in available_command.cli_helpers:
                        #        remaining_commands.append(cli_helper)
                        continue
                    try:
                        if available_command.command[symbol_num] != symbol:
                            if available_command in remaining_commands:
                                remaining_commands.remove(available_command)
                    except IndexError:
                        if available_command in remaining_commands:
                            remaining_commands.remove(available_command)
                symbol_num += 1
            if len(remaining_commands) == 0:
                if not dynamic_command:
                    return False, "% Invalid input"
                current_command = dynamic_command
                completed_command_string.append(command)
                if len(current_command.cli_helpers) > 0:
                    available_commands = current_command.cli_helpers
                else:
                    available_commands = dynamic_command.children
                continue
            if len(remaining_commands) > 1:
                if len(input_symbols) == 0 and get_helper:
                    return True, remaining_commands
                new_remaining_commands = []
                for remaining_command in remaining_commands:
                    if remaining_command.command == command:
                        new_remaining_commands.append(remaining_command)
                remaining_commands = new_remaining_commands
            if len(remaining_commands) == 1:
                current_command = remaining_commands[0]
                completed_command_string.append(current_command.command)
                if current_command.is_cli_helper():
                    next_command = current_command.cli_helped_command
                else:
                    next_command = current_command
                if len(next_command.cli_helpers) > 0:
                    available_commands = next_command.cli_helpers
                else:
                    available_commands = next_command.children
                if dynamic_command and just_complete:
                    if not dynamic_command.parent: continue
                    return True, current_command.command
                continue
            if just_complete:
                common_prefix_list = []
                for remaining_command in remaining_commands:
                    if isinstance(remaining_command, DynamicConfigCommand):
                        continue
                    common_prefix_list.append(remaining_command.command)
                common_prefix = longest_common_prefix(common_prefix_list)
                return True, f'!{common_prefix}'
            if get_helper:
                return True, remaining_commands
            return False, "% Ambiguous command"
        if just_complete is True:
            if dynamic_command:
                return False, None
            return True, current_command.command
        if get_helper:
            return True, current_command
        #if not current_command.cli_command:
        #    return False, "% Incomplete command"
        if delete_config:
            completed_command_string.insert(0, "no")
        
        if len(current_command.children) > 0:
            if delete_config:
                if not current_command.deleter:
                    return False, "% Incomplete command"
            else:
                return False, "% Incomplete command"
        completed_command_string = " ".join(completed_command_string)
        #completed_command_string = current_command.cli_command
        #if dynamic_command:
        #    completed_command_string += f' {command}'
        try:
            same_level_prefix = False
            if current_command.parent_owns_level:
                if self.current_level == current_command.parent:
                    same_level_prefix = True
            else:
                if self.current_level == current_command:
                    same_level_prefix = True
            if same_level_prefix:
                self.level_prefix = self.level_prefix[:-1]
            if current_command in level_reset_commands:
                self.level_prefix = []
            send_command = ["configure"]
            for item in self.level_prefix:
                send_command.append(item)
            send_command.append(completed_command_string)
            command_output = self.api_connection.runCmds( 1, send_command)
            command_output = None
            #print("")
            #print(self.current_level.command)
            #print(send_command)
            if delete_config:
                if len(current_command.nested_commands) > 0:
                    #if current_command.upper_level != "config":
                    if self.current_level == current_command:
                        self.call_exit_handler([], same_level_prefix)
                if current_command.parent_owns_level:
                    if len(current_command.parent.nested_commands) > 0:
                        #if current_command.parent.upper_level != "config":
                        if self.current_level == current_command.parent:
                            self.call_exit_handler([], same_level_prefix)
            if not delete_config:
                if current_command.cli_level:
                    if current_command.parent_owns_level:
                        self.current_level = current_command.parent
                    else:                    
                        self.current_level = current_command
                    self.level_prefix.append(completed_command_string)
                    self.prompt = f'{socket.gethostname()}({current_command.cli_level})#'
        except ConnectionRefusedError:
            command_output = "% Unable to connect to API! Check that Bandwidth Sampler is running."
        except:
            if current_command.command == "asn":
                try:
                    # return error if trying go enter BGP config with wrong ASN
                    current_asn = self.api_connection.runCmds( 1, ["show bgp summary"])[0]["asn"]
                    self.current_level = "config"
                    self.prompt = f'{socket.gethostname()}(config)#'
                    return False, f'% BGP is already running with AS number {current_asn}'
                except:
                    False, "% Invalid input"
            return False, "% Invalid input"

        return True, command_output
    

    def call_show_handler(self, input_symbols, just_complete=False, get_helper=False):
        if len(input_symbols) == 0:
            return False, "% Incomplete command"
        available_commands = global_show_commands
        if self.current_level != "exec" and self.current_level != "config":
            if show_active not in available_commands:
                available_commands.append(show_active)
        current_command = None
        completed_command_string = []
        after_pipe = None
        redirect_to = None
        append_to = None
        while len(input_symbols) > 0:
            remaining_commands = available_commands.copy()
            symbol_num = 0
            dynamic_command = None
            command = input_symbols.pop(0)
            # pipe can be after space or without space
            if "|" in command:
                if command == "|": 
                    after_pipe = " ".join(custom_join(input_symbols))
                    break
                else:
                    split_command = command.split("|")
                    command = split_command[0]
                    input_symbols = ["|"] + split_command[1:] + input_symbols
            # redirect/append must be after space
            if command == ">":
                redirect_to = " ".join(input_symbols)
                break
            if command == ">>":
                append_to = " ".join(input_symbols)
                break
            
            for symbol in command:
                for available_command in available_commands:
                    if isinstance(available_command, DynamicShowCommand): 
                        dynamic_command = available_command
                        if available_command in remaining_commands:
                            remaining_commands.remove(available_command)
                        continue
                    try:
                        if available_command.command[symbol_num] != symbol:
                            if available_command in remaining_commands:
                                remaining_commands.remove(available_command)
                    except IndexError:
                        if available_command in remaining_commands:
                            remaining_commands.remove(available_command)
                symbol_num += 1
            if len(remaining_commands) == 0:
                if not dynamic_command:
                    return False, "% Invalid input"
                current_command = dynamic_command
                completed_command_string.append(command)
                available_commands = dynamic_command.children
                continue
            if len(remaining_commands) == 1:
                current_command = remaining_commands[0]
                completed_command_string.append(current_command.command)
                available_commands = remaining_commands[0].children
                continue
            if just_complete:
                common_prefix_list = []
                for remaining_command in remaining_commands:
                    if isinstance(remaining_command, DynamicShowCommand):
                        continue
                    common_prefix_list.append(remaining_command.command)
                common_prefix = longest_common_prefix(common_prefix_list)
                return True, f'!{common_prefix}'
            if len(remaining_commands) > 1:
                if len(input_symbols) == 0 and get_helper:
                    return True, remaining_commands
                for remaining_command in remaining_commands:
                    if isinstance(remaining_command, ShowCommand):
                        if remaining_command.command == command:
                            completed_command_string.append(command)
                            current_command = remaining_command
                            available_commands = remaining_command.children
                            break
                continue
            if get_helper:
                return True, remaining_commands
            return False, "% Ambiguous command"
        if get_helper:
            return True, current_command
        if just_complete is True:
            # if previous command has static and dynamic children and current autocomplete matches a static child, return it
            if dynamic_command:
                if isinstance(current_command, DynamicShowCommand):
                    return False, None
            return True, current_command.command
        if not current_command:
            return False, "% Invalid command"            
        if not current_command.query:
            return False, "% Incomplete command"
        # a little hack to correctly display show run in CLI
        if completed_command_string == ["running-config"]:
            completed_command_string += ["raw"]
        completed_command_string = "show " + " ".join(custom_join(completed_command_string))
        if completed_command_string == "show active":
            if self.current_level == "exec":
                return False, "% Invalid input"
            config_section = self.level_prefix[-1]
            display_level_prefix = copy.deepcopy(self.level_prefix)
            # temporary workaround to for candidate path and neighbor under traffic-eng nodes
            # so that it wouldn't print output from other policies/nodes
            if config_section.split(" ")[0] == "candidate-path":
                try:
                    config_section = self.level_prefix[-2]
                    display_level_prefix = display_level_prefix[:-1]
                except KeyError:
                    pass
            if config_section.split(" ")[0] == "neighbor":
                try:
                    if display_level_prefix[-2].split(" ")[0] == "node":
                        config_section = self.level_prefix[-2]
                        display_level_prefix = display_level_prefix[:-1]
                except KeyError:
                    pass
            send_command = f'running-config | section {config_section}'
            command_output = ""
            indent = 0
            if len(display_level_prefix) > 1:
                for prefix in display_level_prefix[:-1]:
                    command_output += f'{"   " * indent}{prefix}\n'
                    indent += 1
            _, show_output = self.call_show_handler(send_command.split())
            command_output += show_output
            return True, command_output
        try:
            # request response in binary for better performance
            combined_output = False
            if completed_command_string == "show tech-support":
                combined_output = True
                command_output = ""
                for command_name, command in self.SHOW_TECH_COMMANDS.items():
                    command_output += f'------------- {command_name} -------------\n'
                    command_output += '\n'
                    try:
                        this_command_output = self.api_connection.runCmds( 1, [command_name], "binary")
                        this_command_output = bytes.fromhex(this_command_output)
                        this_command_output = msgpack.loads(this_command_output, raw=False)
                        if not command.printer:
                            this_command_output = f'% Printer not available for command "{command_name}"'
                        else:
                            this_command_output = command.printer(this_command_output[0])
                    except Exception as e:
                        this_command_output = f"% API error when running command {completed_command_string} - exception {e.__class__.__name__, e.args}"
                    if command_name == "show logging":
                        with open("/var/log/srte_bw_sampler.log", "r") as f:
                            this_command_output = f.read()
                    command_output += this_command_output
                    command_output += '\n' *2
            elif completed_command_string == "show logging":
                combined_output = True
                print('\n')
                with open("/var/log/srte_bw_sampler.log", "r") as f:
                    command_output = f.read()
            elif completed_command_string == "show logging recent":
                combined_output = True
                print('\n')
                os.system("tail -n 50 /var/log/srte_bw_sampler.log")
                return True, ""
            elif completed_command_string == "show logging follow":
                try:
                    print('\n')
                    os.system("tail -n 30 -f /var/log/srte_bw_sampler.log")
                    return True, ""
                except KeyboardInterrupt:
                    # Ctrl-c when printing a long output will just kill less to stop printing
                    os.system("killall tail")
                    return True, ""
            else:
                command_output = self.api_connection.runCmds( 1, [completed_command_string], "binary")
                command_output = bytes.fromhex(command_output)
                command_output = msgpack.loads(command_output, raw=False)
            if not current_command.printer and not combined_output:
                command_output = f'% Printer not available for command "{completed_command_string}"'
            else:
                if not combined_output:
                    command_output = current_command.printer(command_output[0])
                if after_pipe:
                    # first check if the command is "section"
                    section = False
                    symbol_num = 0
                    #after_pipe_list = after_pipe.split()
                    after_pipe_list = shlex.split(after_pipe)
                    if len(after_pipe_list) > 1 and len(after_pipe_list[0]) < 8:
                        if after_pipe_list[0] == "section"[:len(after_pipe_list[0])]:
                            section = True
                            after_pipe = " ".join(custom_join(after_pipe_list[1:]))
                    if section:
                        if completed_command_string != "show running-config raw":
                            return False, "% Section option available only for show running-config; please use grep for other commands"
                        filtered_output = []
                        last_section_index = None
                        section_indent = 0
                        output = command_output.splitlines()
                        #for line in output:
                        current_index = 0
                        while current_index <= len(output):
                            try:
                                line = output[current_index]
                                current_index += 1
                                if len(line) == 0: continue
                                #if line[0] != " ":
                                #    last_section_index = output.index(line)
                                if after_pipe in line:
                                    last_section_index = current_index-1
                                    section_indent = len(line) - len(line.lstrip(' '))
                                if after_pipe in line and last_section_index is not None:
                                    #print(output)
                                    for section_line in output[last_section_index:output.index(line)+1]:
                                        current_index += 1
                                        filtered_output.append(section_line)
                                    for section_line in output[output.index(line)+1:]:
                                        current_index += 1
                                        if len(section_line) == 0: continue
                                        if section_line[0] != " ":
                                            current_index -= 1
                                            break
                                        #if section_line.lstrip(' ') == "!": continue
                                        line_indent = len(section_line) - len(section_line.lstrip(' '))
                                        if line_indent <= section_indent: 
                                            current_index -= 1
                                            break
                                        filtered_output.append(section_line)
                                    section_indent = 0
                                    last_section_index = None
                            except IndexError:
                                break
                                
                        command_output = "\n".join(filtered_output)
                    else:
                        print('\n')
                        p1 = subprocess.Popen(["cat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, shell=True)
                        output1, _ = p1.communicate(input=command_output)
                        p2 = subprocess.Popen([after_pipe], stdin=subprocess.PIPE, text=True, shell=True)
                        p2.communicate(input=output1)
                        command_output = None
                if redirect_to:
                    if len(redirect_to.split(" ")) > 1:
                        return False, "% Invalid input"
                    p = subprocess.Popen(["cat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
                    output, _ = p.communicate(input=command_output)
                    output = output.splitlines()

                    with open(redirect_to, "w") as output_file:
                        for line in output:
                            output_file.write(f'{line}\n')
                    command_output = None
                if append_to:
                    if len(append_to.split(" ")) > 1:
                        return False, "% Invalid input"
                    p = subprocess.Popen(["cat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
                    output, _ = p.communicate(input=command_output)
                    output = output.splitlines()
                    with open(append_to, "a") as output_file:
                        for line in output:
                            output_file.write(f'{line}\n')
                    command_output = None

        except ConnectionRefusedError:
            command_output = "% Unable to connect to API! Check that Bandwidth Sampler is running."
        except Exception as e:
            command_output = f"% API error when running command {completed_command_string} - exception {e.__class__.__name__, e.args}"

          
        return True, command_output



    def call_clear_handler(self, input_symbols, just_complete=False, get_helper=False):
        if len(input_symbols) == 0:
            return False, "% Incomplete command"
        available_commands = global_clear_commands
        current_command = None
        completed_command_string = []
        while len(input_symbols) > 0:
            remaining_commands = available_commands.copy()
            symbol_num = 0
            dynamic_command = None
            command = input_symbols.pop(0)         
            for symbol in command:
                for available_command in available_commands:
                    if isinstance(available_command, DynamicClearCommand): 
                        dynamic_command = available_command
                        if available_command in remaining_commands:
                            remaining_commands.remove(available_command)
                        continue
                    try:
                        if available_command.command[symbol_num] != symbol:
                            if available_command in remaining_commands:
                                remaining_commands.remove(available_command)
                    except IndexError:
                        if available_command in remaining_commands:
                            remaining_commands.remove(available_command)
                symbol_num += 1
            if len(remaining_commands) == 0:
                if not dynamic_command:
                    return False, "% Invalid input"
                current_command = dynamic_command
                completed_command_string.append(command)
                available_commands = dynamic_command.children
                continue
            if len(remaining_commands) == 1:
                current_command = remaining_commands[0]
                completed_command_string.append(current_command.command)
                available_commands = remaining_commands[0].children
                continue
            if len(remaining_commands) > 1:
                if len(input_symbols) == 0 and get_helper:
                    return True, remaining_commands
            if just_complete:
                common_prefix_list = []
                for remaining_command in remaining_commands:
                    if isinstance(remaining_command, DynamicClearCommand):
                        continue
                    common_prefix_list.append(remaining_command.command)
                common_prefix = longest_common_prefix(common_prefix_list)
                return True, f'!{common_prefix}'
            if get_helper:
                return True, remaining_commands
            return False, "% Ambiguous command" 
        if get_helper:
            return True, current_command   
        if just_complete is True:
            if dynamic_command:
                return False, None
            return True, current_command.command
        if not current_command.query:
            return False, "% Incomplete command"
        completed_command_string = "clear " + " ".join(completed_command_string)
        try:
            command_output = self.api_connection.runCmds( 1, [completed_command_string])
            command_output = command_output[0]["warnings"][0]
        except ConnectionRefusedError:
            command_output = "% Unable to connect to API! Check that Bandwidth Sampler is running."
        except Exception as e:
            command_output = f"% API error when running command {completed_command_string} - exception {e.__class__.__name__, e.args}"

        return True, command_output


    def call_debug_handler(self, input_symbols, just_complete=False, get_helper=False):
        if len(input_symbols) == 0:
            return False, "% Incomplete command"
        available_commands = global_debug_commands
        current_command = None
        completed_command_string = []
        while len(input_symbols) > 0:
            remaining_commands = available_commands.copy()
            symbol_num = 0
            dynamic_command = None
            command = input_symbols.pop(0)         
            for symbol in command:
                for available_command in available_commands:
                    if isinstance(available_command, DynamicDebugCommand): 
                        dynamic_command = available_command
                        if available_command in remaining_commands:
                            remaining_commands.remove(available_command)
                        continue
                    try:
                        if available_command.command[symbol_num] != symbol:
                            if available_command in remaining_commands:
                                remaining_commands.remove(available_command)
                    except IndexError:
                        if available_command in remaining_commands:
                            remaining_commands.remove(available_command)
                symbol_num += 1
            if len(remaining_commands) == 0:
                if not dynamic_command:
                    return False, "% Invalid input"
                current_command = dynamic_command
                completed_command_string.append(command)
                available_commands = dynamic_command.children
                continue
            if len(remaining_commands) == 1:
                current_command = remaining_commands[0]
                completed_command_string.append(current_command.command)
                available_commands = remaining_commands[0].children
                continue
            if len(remaining_commands) > 1:
                if len(input_symbols) == 0 and get_helper:
                    return True, remaining_commands
            if just_complete:
                common_prefix_list = []
                for remaining_command in remaining_commands:
                    if isinstance(remaining_command, DynamicDebugCommand):
                        continue
                    common_prefix_list.append(remaining_command.command)
                common_prefix = longest_common_prefix(common_prefix_list)
                return True, f'!{common_prefix}'
            if get_helper:
                return True, remaining_commands
            return False, "% Ambiguous command"
        if get_helper:
            return True, current_command
        if just_complete is True:
            if dynamic_command:
                return False, None
            return True, current_command.command
        if not current_command.query:
            return False, "% Incomplete command"
        completed_command_string = "debug " + " ".join(completed_command_string)
        try:
            command_output = self.api_connection.runCmds( 1, [completed_command_string])
            # handle debug all 
            if isinstance(command_output[0], list):
                new_command_output = ""
                for item in command_output[0]:
                    new_command_output += f'{item["warnings"][0]}\n'
                command_output = new_command_output
            else:
                command_output = command_output[0]["warnings"][0]
        except ConnectionRefusedError:
            command_output = "% Unable to connect to API! Check that Bandwidth Sampler is running."
        except Exception as e:
            command_output = f"% API error when running command {completed_command_string} - exception {e.__class__.__name__, e.args}"

        return True, command_output


    def call_undebug_handler(self, input_symbols, just_complete=False, get_helper=False):
        if len(input_symbols) == 0:
            return False, "% Incomplete command"
        available_commands = global_debug_commands
        current_command = None
        completed_command_string = []
        while len(input_symbols) > 0:
            remaining_commands = available_commands.copy()
            symbol_num = 0
            dynamic_command = None
            command = input_symbols.pop(0)         
            for symbol in command:
                for available_command in available_commands:
                    if isinstance(available_command, DynamicDebugCommand): 
                        dynamic_command = available_command
                        if available_command in remaining_commands:
                            remaining_commands.remove(available_command)
                        continue
                    try:
                        if available_command.command[symbol_num] != symbol:
                            if available_command in remaining_commands:
                                remaining_commands.remove(available_command)
                    except IndexError:
                        if available_command in remaining_commands:
                            remaining_commands.remove(available_command)
                symbol_num += 1
            if len(remaining_commands) == 0:
                if not dynamic_command:
                    return False, "% Invalid input"
                current_command = dynamic_command
                completed_command_string.append(command)
                available_commands = dynamic_command.children
                continue
            if len(remaining_commands) == 1:
                current_command = remaining_commands[0]
                completed_command_string.append(current_command.command)
                available_commands = remaining_commands[0].children
                continue
            if len(remaining_commands) > 1:
                if len(input_symbols) == 0 and get_helper:
                    return True, remaining_commands
            if just_complete:
                common_prefix_list = []
                for remaining_command in remaining_commands:
                    if isinstance(remaining_command, DynamicDebugCommand):
                        continue
                    common_prefix_list.append(remaining_command.command)
                common_prefix = longest_common_prefix(common_prefix_list)
                return True, f'!{common_prefix}'
            if get_helper:
                return True, remaining_commands
            return False, "% Ambiguous command"
        if get_helper:
            return True, current_command
        if just_complete is True:
            if dynamic_command:
                return False, None
            return True, current_command.command
        if not current_command.query:
            return False, "% Incomplete command"
        completed_command_string = "undebug " + " ".join(completed_command_string)
        try:
            command_output = self.api_connection.runCmds( 1, [completed_command_string])
            # handle undebug all 
            if isinstance(command_output[0], list):
                new_command_output = ""
                for item in command_output[0]:
                    new_command_output += f'{item["warnings"][0]}\n'
                command_output = new_command_output
            else:
                command_output = command_output[0]["warnings"][0]
        except ConnectionRefusedError:
            command_output = "% Unable to connect to API! Check that Bandwidth Sampler is running."
        except Exception as e:
            command_output = f"% API error when running command {completed_command_string} - exception {e.__class__.__name__, e.args}"

        return True, command_output
    

    def call_write_handler(self, input_symbols, just_complete=False, get_helper=False):
        if len(input_symbols) > 0:
            return False, "% Invalid input"
        try:
            command_output = self.api_connection.runCmds( 1, ["write"])
            command_output = command_output[0]["messages"][0]
        except ConnectionRefusedError:
            command_output = "% Unable to connect to API! Check that Bandwidth Sampler is running."
        except Exception as e:
            command_output = f"% API error when running command write - exception {e.__class__.__name__, e.args}"              
        
        return True, command_output
    
    def call_exit_handler(self, input_symbols, same_level_prefix=False, just_complete=False, get_helper=False):
        if len(input_symbols) > 0:
            return False, "% Invalid input"
        
        if self.current_level == "config":
            self.current_level = "exec"
            self.prompt = f'{socket.gethostname()}#'
            self.level_prefix = []
            return True, None
        if self.current_level != "exec":
            if self.current_level.upper_level == "config":
                self.prompt = f'{socket.gethostname()}(config)#'
                self.current_level = "config"
                self.level_prefix = []
            else:
                self.prompt = f'{socket.gethostname()}({self.current_level.upper_level.cli_level})#'
                self.current_level = self.current_level.upper_level
                if len(self.level_prefix) > 1 and not same_level_prefix:
                    self.level_prefix = self.level_prefix[:-1]
            return True, None
        
        self.exit = True
        return True, "### Goodbye! ###"
    
    def call_end_handler(self, input_symbols, just_complete=False, get_helper=False):
        if len(input_symbols) > 0:
            return False, "% Invalid input"
        if self.current_level == "exec":
            return False, "% Invalid input"
        self.current_level = "exec"
        self.prompt = f'{socket.gethostname()}#'
        self.level_prefix = []
        return True, None
    
    def call_ping_handler(self, input_symbols, just_complete=False, get_helper=False):
        if get_helper: return True, None
        print("")
        input_symbols = ["ping"] + input_symbols
        return self.call_bash_handler(input_symbols, just_complete)
    
    def call_traceroute_handler(self, input_symbols, just_complete=False, get_helper=False):
        if get_helper: return True, None
        print("")
        input_symbols = ["traceroute"] + input_symbols
        return self.call_bash_handler(input_symbols, just_complete)
    
    def call_tcpdump_handler(self, input_symbols, just_complete=False, get_helper=False):
        if get_helper: return True, None
        print("")
        input_symbols = ["tcpdump"] + input_symbols
        return self.call_bash_handler(input_symbols, just_complete)        

    def call_terminal_handler(self, input_symbols, just_complete=False, get_helper=False):
        # for now just supports terminal length <0-32767>
        if len(input_symbols) != 2:
            return False, "% Invalid input"
        if len(input_symbols[0]) > 0 and len(input_symbols[0]) < 7:
            if input_symbols[0] == "length"[:len(input_symbols[0])]:
                try:
                    terminal_length = int(input_symbols[1])
                    if terminal_length >=0 and terminal_length < 32768:
                        self.terminal_length = terminal_length
                        return True, None
                except:
                    False, "% Invalid input"
        return False, "% Invalid input"

    def call_bash_handler(self, input_symbols, just_complete=False, get_helper=False):
        if get_helper: return True, None
        print("")
        if len(input_symbols) == 0:
            os.system("bash")
        bash_output = os.system(" ".join(input_symbols))
        if bash_output == 0:
            return True, None
        print(f'% {" ".join(input_symbols)} returned error code: {bash_output}')
        return False, None

    COMMAND_HANDLERS = {
        "configure": call_configure_handler,
        "show": call_show_handler,
        "clear": call_clear_handler,
        "debug": call_debug_handler,
        "undebug": call_undebug_handler,
        "write": call_write_handler,
        "exit": call_exit_handler,
        "end": call_end_handler,
        "bash": call_bash_handler,
        "ping": call_ping_handler,
        "traceroute": call_traceroute_handler,
        "tcpdump": call_tcpdump_handler,
        "terminal": call_terminal_handler
    }

    def autocomplete_first_command(self, first_command, ignore_exec=False, current_level=None, just_complete=False, get_helper=False):
        symbol_num = 0
        if not current_level:
            current_level = self.current_level
        if current_level == "exec":
            available_commands = list(self.COMMAND_HANDLERS.keys())
            available_commands.remove("end")
            remaining_commands = available_commands.copy()
            for symbol in first_command:
                for available_command in available_commands:
                    try:
                        if available_command[symbol_num] != symbol:
                            if available_command in remaining_commands:
                                remaining_commands.remove(available_command)
                    except IndexError:
                        if available_command in remaining_commands:
                            remaining_commands.remove(available_command)
                symbol_num += 1
            if len(remaining_commands) == 0:
                return False, "% Invalid input"
            if len(remaining_commands) == 1:
                return True, remaining_commands[0]
            if first_command in remaining_commands:
                return True, first_command
            if just_complete:
                common_prefix = longest_common_prefix(remaining_commands)
                return True, f'!{common_prefix}'
            if get_helper:
                return True, remaining_commands
            return False, "% Ambiguous command"
        else:
            if not ignore_exec:
                available_commands = list(self.COMMAND_HANDLERS.keys())
                available_commands.append("do")
                available_commands.append("no")
                available_commands.remove("end")
            else:
                available_commands = []
            if current_level == "config":
                for global_command in global_commands:
                    available_commands.append(global_command.command)
            else:
                for nested_command in current_level.nested_commands:
                    available_commands.append(nested_command.command)
                for global_command in global_commands:
                    if global_command.command not in available_commands:
                        available_commands.append(global_command.command)
            remaining_commands = available_commands.copy()
            for symbol in first_command:
                for available_command in available_commands:
                    try:
                        if available_command[symbol_num] != symbol:
                            if available_command in remaining_commands:
                                remaining_commands.remove(available_command)
                    except IndexError:
                        if available_command in remaining_commands:
                            remaining_commands.remove(available_command)
                symbol_num += 1
            if len(remaining_commands) == 0:
                return False, "% Invalid input"
            if len(remaining_commands) == 1:
                return True, remaining_commands[0]
            if first_command in remaining_commands:
                return True, first_command
            for remaining_command in remaining_commands:
                if isinstance(remaining_command, ConfigCommand):
                    if remaining_command.command == first_command:
                        return True, first_command
            if just_complete:
                common_prefix = longest_common_prefix(remaining_commands)
                return True, f'!{common_prefix}'
            if get_helper:
                return True, remaining_commands
            return False, "% Ambiguous command"            
                


    def process_input_commands(self, input_symbols, just_complete=False, get_helper=False):
        #input_symbols = "".join(input_symbols)
        #input_symbols = input_symbols.split()
        try:
            input_symbols = shlex.split(input_symbols)
        except:
            return False, "% Invalid input"
        if len(input_symbols) == 0:
            return False, None

        if input_symbols[0] == "!": return True, None

        if self.current_level == "exec":
            first_command = input_symbols.pop(0)
            result, first_command = self.autocomplete_first_command(first_command)
            if result is False:
                return False, first_command
            if first_command not in self.COMMAND_HANDLERS.keys():
                return False, "% Invalid input"
            handler = self.COMMAND_HANDLERS[first_command]
            return handler(self, input_symbols, just_complete, get_helper)
        else:
            first_command = input_symbols.pop(0)
            if first_command == "end" and len(input_symbols) == 0:
                return self.call_end_handler(input_symbols)
            result, first_command = self.autocomplete_first_command(first_command)
            if result is False:
                return False, first_command
            if first_command == "do":
                if len(input_symbols) == 0: return False, "% Incomplete command"
                second_command = input_symbols.pop(0)
                result, second_command = self.autocomplete_first_command(second_command, ignore_exec=False, current_level="exec")
                if result is False:
                    return False, second_command   
                if second_command not in self.COMMAND_HANDLERS.keys():
                    return False, "% Invalid input"
                handler = self.COMMAND_HANDLERS[second_command]
                return handler(self, input_symbols, just_complete, get_helper)
            if first_command == "no":
                if len(input_symbols) == 0: return False, "% Incomplete command"
                second_command = input_symbols.pop(0)
                result, second_command = self.autocomplete_first_command(second_command, ignore_exec=True)
                if result is False:
                    return False, second_command
                return self.call_config_handler(second_command, input_symbols, just_complete, get_helper, delete_config=True)
            if first_command not in self.COMMAND_HANDLERS.keys():
                return self.call_config_handler(first_command, input_symbols, just_complete, get_helper)
            handler = self.COMMAND_HANDLERS[first_command]
            return handler(self, input_symbols, just_complete, get_helper)

    EXEC_FIRST_COMMAND_HELPERS = {
        "configure": "Config mode",
        "show": "Show command",
        "clear": "Clear command",
        "debug": "Enable debug",
        "undebug": "Disable debug",
        "write": "Save configuration",
        "exit": "Exit CLI",
        "bash": "Run bash command",
        "ping": "Ping remote host",
        "traceroute": "Traceroute to remote host",
        "tcpdump": "Capture traffic",
        "terminal": "Set terminal settings"        
    }

    EXEC_FIRST_COMMAND_DETAILS = {
        "configure": [{'<cr>': ""}],
        "show": global_show_commands,
        "clear": global_clear_commands,
        "debug": global_debug_commands,
        "undebug": global_debug_commands,
        "write": [{'<cr>': ""}],
        "exit": [{'<cr>': ""}],
        "bash": [{'ARG': "Arguments to bash command"}, {'<cr>': ""}],
        "ping": [{'ARG': "IP address or hostname"}],
        "traceroute": [{'ARG': "IP address or hostname"}],
        "tcpdump": [{'ARG': "Tcpdump arguments"}, {'<cr>': ""}],
        "terminal": [{'length': "Set terminal length"}]    
    }

    def read_input_line(self):
        input_symbols = []
        cursor_position = 0
        print(self.prompt, end="")
        while True:
            symbol = read_single_keypress()
            if symbol[0] == "?":
                sys.stdout.write("?")
                # context help
                command_text = "".join(input_symbols)
                print_full_help = False
                if len(command_text.split()) == 0:
                    print("")
                    if self.current_level == "exec":
                        for k, v in self.EXEC_FIRST_COMMAND_HELPERS.items():
                            print(f'  {k:20} {v}')
                    elif self.current_level == "config":
                        for available_command in global_commands:
                            print(f'  {available_command.command:20} {available_command.cli_context_help}')
                        print(f'  {"exit":20} Leave configure mode')
                    else:
                        for available_command in self.current_level.nested_commands:
                            print(f'  {available_command.command:20} {available_command.cli_context_help}')
                        print(f'  {"exit":20} Leave current level configuration mode')
                    print("")
                    print(self.prompt, end="")
                    continue
                #if command_text[-1] == " ": continue
                if command_text[-1] == " ":
                    command_text = command_text.split()
                    if len(command_text) == 1 and command_text[0] == "do" and self.current_level != "exec":
                        print("")
                        for k, v in self.EXEC_FIRST_COMMAND_HELPERS.items():
                            print(f'  {k:20} {v}')                   
                        print("")
                        print_data = f'{self.prompt}{"".join(input_symbols)}'
                        print(print_data, end="")
                        continue
                    if len(command_text) == 1 and command_text[0] == "no" and self.current_level != "exec":
                        print("")
                        for available_command in global_commands:
                            print(f'  {available_command.command:20} {available_command.cli_context_help}')                 
                        print("")
                        print_data = f'{self.prompt}{"".join(input_symbols)}'
                        print(print_data, end="")
                        continue
                    print_full_help = True
                    command_text = " ".join(command_text)
                command_text = command_text.split()
                last_command = command_text[-1]
                if len(command_text) == 1:
                    result, completed_command = self.autocomplete_first_command(last_command, get_helper=True)
                    if result is not True: 
                        print(f'\n% Unrecognized command')
                        print_data = f'{self.prompt}{"".join(input_symbols)}'
                        print(print_data, end="")
                        continue
                    if type(completed_command) == str:
                        if print_full_help:
                            if self.current_level == "exec":
                                if completed_command not in self.EXEC_FIRST_COMMAND_DETAILS.keys():
                                    print(f'\n% Unrecognized command')
                                    print_data = f'{self.prompt}{"".join(input_symbols)}'
                                    print(print_data, end="")
                                    continue
                                print("")
                                for helper in self.EXEC_FIRST_COMMAND_DETAILS[completed_command]:
                                    if isinstance(helper, collections.abc.Mapping):
                                        for k, v in helper.items():
                                            print(f'  {k:20} {v}')
                                    else:
                                        print(f'  {helper.command:20} {helper.cli_context_help}')                   
                                print("")
                                print_data = f'{self.prompt}{"".join(input_symbols)}'
                                print(print_data, end="")
                                continue
                            elif self.current_level == "config":
                                if completed_command == "exit":
                                    print("")
                                    print(f'  <cr>')  
                                    print("")
                                    print_data = f'{self.prompt}{"".join(input_symbols)}'
                                    print(print_data, end="")
                                    continue 
                                if completed_command == "show":
                                    print("")
                                    for helper in global_show_commands:
                                        print(f'  {helper.command:20} {helper.cli_context_help}') 
                                    print("")
                                    print_data = f'{self.prompt}{"".join(input_symbols)}'
                                    print(print_data, end="")
                                    continue                                    
                                command_found = False
                                for available_command in global_commands:
                                    if completed_command == available_command.command:
                                        command_found = True
                                        print("")
                                        for child_command in available_command.children:
                                            print(f'  {child_command.command:20} {child_command.cli_context_help}')  
                                        if available_command.new_level or available_command.new_config:
                                            print(f'  <cr>')  
                                        print("")
                                        print_data = f'{self.prompt}{"".join(input_symbols)}'
                                        print(print_data, end="")
                                        break
                                if command_found: continue
                                print(f'\n% Unrecognized command')
                                print_data = f'{self.prompt}{"".join(input_symbols)}'
                                print(print_data, end="")
                                continue
                            else:
                                if completed_command == "exit":
                                    print("")
                                    print(f'  <cr>')  
                                    print("")
                                    print_data = f'{self.prompt}{"".join(input_symbols)}'
                                    print(print_data, end="")
                                    continue
                                if completed_command == "show":
                                    print("")
                                    for helper in global_show_commands:
                                        print(f'  {helper.command:20} {helper.cli_context_help}') 
                                    print(f'  {show_active.command:20} {show_active.cli_context_help}')
                                    print("")
                                    print_data = f'{self.prompt}{"".join(input_symbols)}'
                                    print(print_data, end="")
                                    continue     
                                command_found = False
                                for available_command in self.current_level.nested_commands:
                                    if completed_command == available_command.command:
                                        command_found = True
                                        print("")
                                        for child_command in available_command.children:
                                            if isinstance(child_command, DynamicConfigCommand):
                                                # specifically for AF config under router bgp
                                                if isinstance(child_command.cli_allowed_args, collections.abc.Mapping):
                                                    for k, v in child_command.cli_allowed_args.items():
                                                        print(f'  {k:20} {v}')
                                                else:
                                                    print(f'  {child_command.cli_allowed_args:20} {child_command.cli_context_help}')
                                            else:
                                                print(f'  {child_command.command:20} {child_command.cli_context_help}')  
                                        if available_command.new_level:
                                            print(f'  <cr>')
                                        elif available_command.new_config:
                                            if len(available_command.children) == 0:
                                                print(f'  <cr>')
                                        print("")
                                        print_data = f'{self.prompt}{"".join(input_symbols)}'
                                        print(print_data, end="")
                                        break
                                if command_found: continue
                                print(f'\n% Unrecognized command')
                                print_data = f'{self.prompt}{"".join(input_symbols)}'
                                print(print_data, end="")
                                continue
                        print(f'\n{completed_command}')
                        print("")
                        print_data = f'{self.prompt}{"".join(input_symbols)}'
                        print(print_data, end="")
                        continue
                    else:
                        # if multiple commands possible, and user typed space after that - command is ambiguous
                        if print_full_help:
                            print(f'\n% Ambiguous command')
                            print_data = f'{self.prompt}{"".join(input_symbols)}'
                            print(print_data, end="")
                            continue
                        print(f'\n{"  ".join(completed_command)}')
                        print("")
                        print_data = f'{self.prompt}{"".join(input_symbols)}'
                        print(print_data, end="")
                        continue                        

                if len(command_text) == 2:
                    if command_text[0] == "no" or command_text[0] == "do":
                        if command_text[0] == "no":
                            result, completed_command = self.autocomplete_first_command(last_command, ignore_exec=True, get_helper=True)
                        else:
                            result, completed_command = self.autocomplete_first_command(last_command, get_helper=True)
                        if result is not True:
                            print(f'\n% Unrecognized command')
                            print_data = f'{self.prompt}{"".join(input_symbols)}'
                            print(print_data, end="")
                            continue
                        if type(completed_command) == str:
                            if print_full_help:
                                if command_text[0] == "do":
                                    if completed_command not in self.EXEC_FIRST_COMMAND_DETAILS.keys():
                                        print(f'\n% Unrecognized command')
                                        print_data = f'{self.prompt}{"".join(input_symbols)}'
                                        print(print_data, end="")
                                        continue
                                    print("")
                                    for helper in self.EXEC_FIRST_COMMAND_DETAILS[completed_command]:
                                        if isinstance(helper, collections.abc.Mapping):
                                            for k, v in helper.items():
                                                print(f'  {k:20} {v}')
                                        else:
                                            print(f'  {helper.command:20} {helper.cli_context_help}')                   
                                    print("")
                                    print_data = f'{self.prompt}{"".join(input_symbols)}'
                                    print(print_data, end="")
                                    continue
                                elif self.current_level == "config":
                                    command_found = False
                                    for available_command in global_commands:
                                        if completed_command == available_command.command:
                                            command_found = True
                                            print("")
                                            for child_command in available_command.children:
                                                print(f'  {child_command.command:20} {child_command.cli_context_help}')  
                                            if available_command.new_level:
                                                print(f'  <cr>')
                                            elif available_command.new_config:
                                                if len(available_command.children) == 0:
                                                    print(f'  <cr>')
                                            print("")
                                            print_data = f'{self.prompt}{"".join(input_symbols)}'
                                            print(print_data, end="")
                                            break
                                    if command_found: continue
                                    print(f'\n% Unrecognized command')
                                    print_data = f'{self.prompt}{"".join(input_symbols)}'
                                    print(print_data, end="")
                                    continue
                                else:
                                    command_found = False
                                    for available_command in self.current_level.nested_commands:
                                        if completed_command == available_command.command:
                                            command_found = True
                                            print("")
                                            for child_command in available_command.children:
                                                if isinstance(child_command, DynamicConfigCommand):
                                                    # specifically for AF config under router bgp
                                                    if isinstance(child_command.cli_allowed_args, collections.abc.Mapping):
                                                        for k, v in child_command.cli_allowed_args.items():
                                                            print(f'  {k:20} {v}')
                                                    else:
                                                        print(f'  {child_command.cli_allowed_args:20} {child_command.cli_context_help}')
                                                else:
                                                    print(f'  {child_command.command:20} {child_command.cli_context_help}')  
                                            if available_command.new_level or available_command.new_config:
                                                print(f'  <cr>')  
                                            print("")
                                            print_data = f'{self.prompt}{"".join(input_symbols)}'
                                            print(print_data, end="")
                                            break
                                    if command_found: continue
                                    print(f'\n% Unrecognized command')
                                    print_data = f'{self.prompt}{"".join(input_symbols)}'
                                    print(print_data, end="")
                                    continue
                            print(f'\n{completed_command}')
                            print("")
                            print_data = f'{self.prompt}{"".join(input_symbols)}'
                            print(print_data, end="")
                            continue
                        else:
                            # if multiple commands possible, and user typed space after that - command is ambiguous
                            if print_full_help:
                                print(f'\n% Ambiguous command')
                                print_data = f'{self.prompt}{"".join(input_symbols)}'
                                print(print_data, end="")
                                continue
                            print(f'\n{"  ".join(completed_command)}')
                            print("")
                            print_data = f'{self.prompt}{"".join(input_symbols)}'
                            print(print_data, end="")
                            continue
                result, completed_command = self.process_input_commands("".join(input_symbols), get_helper=True)
                if result is not True:
                    print(f'\n% Unrecognized command')
                    print_data = f'{self.prompt}{"".join(input_symbols)}'
                    print(print_data, end="")
                    continue
                if completed_command is None:
                    if print_full_help:
                        print("")
                        print(f'  {"ARG":20} {"Executable arguments"}')                   
                        print("")
                        print_data = f'{self.prompt}{"".join(input_symbols)}'
                        print(print_data, end="")
                        continue
                    else:
                        print(f'\nARG')
                        print("")
                        print_data = f'{self.prompt}{"".join(input_symbols)}'
                        print(print_data, end="")
                        continue                            
                if type(completed_command) == list:
                    # if multiple commands possible, and user typed space after that - command is ambiguous
                    if print_full_help:
                        print(f'\n% Ambiguous command')
                        print_data = f'{self.prompt}{"".join(input_symbols)}'
                        print(print_data, end="")
                        continue
                    command_list = []
                    for command in completed_command:
                        command_list.append(command.command)
                    print(f'\n{"  ".join(command_list)}')
                    print("")
                    print_data = f'{self.prompt}{"".join(input_symbols)}'
                    print(print_data, end="")
                    continue
                else:
                    if print_full_help:
                        print("")
                        for child_command in completed_command.children:
                            if isinstance(child_command, DynamicConfigCommand) or isinstance(child_command, DynamicShowCommand) or isinstance(child_command, DynamicClearCommand) or isinstance(child_command, DynamicDebugCommand):
                                # specifically for AF config under router bgp
                                if isinstance(child_command.cli_allowed_args, collections.abc.Mapping):
                                    for k, v in child_command.cli_allowed_args.items():
                                        print(f'  {k:20} {v}')
                                else:
                                    print(f'  {child_command.cli_allowed_args:20} {child_command.cli_context_help}')
                            else:
                                print(f'  {child_command.command:20} {child_command.cli_context_help}')
                        if isinstance(completed_command, ConfigCommand):
                            if completed_command.new_level or completed_command.new_config:
                                print(f'  <cr>')
                            elif completed_command.is_cli_helper() and len(completed_command.children) == 0:
                                print(f'  <cr>')
                        else:
                            if completed_command.query:
                                print(f'  <cr>')
                        print("")
                        print_data = f'{self.prompt}{"".join(input_symbols)}'
                        print(print_data, end="")
                        continue
                    if isinstance(completed_command, DynamicConfigCommand) or isinstance(completed_command, DynamicShowCommand) or isinstance(completed_command, DynamicClearCommand) or isinstance(completed_command, DynamicDebugCommand):
                        # specifically for AF config under router bgp
                        if isinstance(completed_command.cli_allowed_args, collections.abc.Mapping):
                            for k, v in completed_command.cli_allowed_args.items():
                                print(f'  {k:20} {v}')
                        else:
                            print(f'\n{completed_command.cli_allowed_args}')
                    else:
                        print(f'\n{completed_command.command}')
                    print("")
                    print_data = f'{self.prompt}{"".join(input_symbols)}'
                    print(print_data, end="")
                    continue
            elif symbol[0] == "\t":
                # Tab
                command_text = "".join(input_symbols)
                if len(command_text) == 0: continue
                if command_text[-1] == " ": continue
                command_text = command_text.split()
                last_command = command_text[-1]
                if len(command_text) == 1:
                    result, completed_command = self.autocomplete_first_command(last_command, just_complete=True)
                    if result is not True: continue
                    already_input_length = len(last_command)
                    # "!" is a special hack for the case when autocomplete doesn't return a command but just a common prefix
                    # so that we don't print space after that
                    ambiguous_command = False
                    if completed_command[0] == "!":
                        ambiguous_command = True
                        completed_command = completed_command[1:]
                    for symbol in completed_command[already_input_length:]:
                        sys.stdout.write(symbol)
                        input_symbols.insert(cursor_position, symbol)
                        cursor_position += 1
                    if not ambiguous_command:
                        sys.stdout.write(" ")
                        input_symbols.insert(cursor_position, " ")
                        cursor_position += 1
                    continue
                if len(command_text) == 2:
                    if command_text[0] == "no" or command_text[0] == "do":
                        if command_text[0] == "no":
                            result, completed_command = self.autocomplete_first_command(last_command, ignore_exec=True, just_complete=True)
                        else:
                            result, completed_command = self.autocomplete_first_command(last_command, just_complete=True)
                        if result is not True: continue
                        already_input_length = len(last_command)
                        ambiguous_command = False
                        if completed_command[0] == "!":
                            ambiguous_command = True
                            completed_command = completed_command[1:]
                        for symbol in completed_command[already_input_length:]:
                            sys.stdout.write(symbol)
                            input_symbols.insert(cursor_position, symbol)
                            cursor_position += 1
                        if not ambiguous_command:
                            sys.stdout.write(" ")
                            input_symbols.insert(cursor_position, " ")
                            cursor_position += 1
                        continue
                result, completed_command = self.process_input_commands("".join(input_symbols), just_complete=True)
                if result is not True: continue
                already_input_length = len(last_command)
                # "!" is a special hack for the case when autocomplete doesn't return a command but just a common prefix
                # so that we don't print space after that
                ambiguous_command = False
                if completed_command[0] == "!":
                    ambiguous_command = True
                    completed_command = completed_command[1:]
                for symbol in completed_command[already_input_length:]:
                    sys.stdout.write(symbol)
                    input_symbols.insert(cursor_position, symbol)
                    cursor_position += 1
                if not ambiguous_command:
                    sys.stdout.write(" ")
                    input_symbols.insert(cursor_position, " ")
                    cursor_position += 1
                continue
            elif symbol[0] == "\r" or symbol[0] == "\n":
                # Enter
                command_text = "".join(input_symbols)
                command_text = command_text.strip()
                if len(command_text) > 0:
                    if self.current_level == "exec":
                        if len(self.command_history_exec) > 0:
                            if command_text != self.command_history_exec[-1]:
                                self.command_history_exec.append(command_text)
                        else:
                            self.command_history_exec.append(command_text)
                    else:
                        if len(self.command_history_config) > 0:
                            if command_text != self.command_history_config[-1]:
                                self.command_history_config.append(command_text)
                        else:
                            self.command_history_config.append(command_text)
                if self.current_level == "exec":
                    self.historic_command_number_exec = 1
                else:
                    self.historic_command_number_config = 1
                result, message = self.process_input_commands(command_text)
                if message is None:
                    print("")
                    return
                if result is False:
                    print(f'\n{message}')
                    return
                if len(message.split('\n')) > self.terminal_length and self.terminal_length != 0:
                    try:
                        print('\n')
                        p1 = subprocess.Popen(["cat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, shell=True)
                        output1, _ = p1.communicate(input=message)
                        p2 = subprocess.Popen(["less -X"], stdin=subprocess.PIPE, text=True, shell=True)
                        p2.communicate(input=output1)
                    except KeyboardInterrupt:
                        # Ctrl-c when printing a long output will just kill less to stop printing
                        os.system("killall less")
                else:
                    print(f'\n{message}')
                return
            elif symbol[0] == "\x03":
                # Ctrl-C
                #   
                sys.stdout.write("\033[K")
                if self.current_level != "exec":
                    self.current_level = "exec"
                    self.prompt = f'{socket.gethostname()}#'
                    self.level_prefix = []
                print("")
                return
            elif symbol[0] == "\x01":
                # Ctrl-A
                # Goto BEGINNING of command line
                while cursor_position > 0:
                    sys.stdout.write("\b")
                    cursor_position -= 1
            elif symbol[0] == "\x05":
                # Ctrl-E
                # Goto END of command line
                while cursor_position < len(input_symbols):
                    sys.stdout.write("\x1b[C")
                    cursor_position += 1
            elif symbol[0] == "\x02":
                # Ctrl-B
                # move back one character
                if cursor_position > 0:
                    sys.stdout.write("\b")
                    cursor_position -= 1
            elif symbol[0] == "\x06":
                # Ctrl-F
                # move forward one character
                if cursor_position < len(input_symbols):
                    sys.stdout.write("\x1b[C")
                    cursor_position += 1
            elif symbol[0] == "\x04":
                # Ctrl-D
                # Delete the character under the cursor
                # if line is empty - exit shell
                if len(input_symbols) == 0:
                    self.current_level = "exec"
                    print("")
                    print(self.call_exit_handler([])[1])
                    return
            elif symbol[0] == "\x15":
                # Ctrl-U
                # Clear all / cut BEFORE cursor
                while cursor_position > 0:
                    # move cursor
                    sys.stdout.write("\b")
                    cursor_position -= 1
                    # erase from cursor to end of line
                    sys.stdout.write("\033[0K")
                    
                    # if there are characters after deleted character, print them again and move cursor back
                    del input_symbols[cursor_position]
                    for character in input_symbols[cursor_position:]:
                        sys.stdout.write(character)
                    for character in input_symbols[cursor_position:]:
                        sys.stdout.write("\b")
            elif symbol[0] == "\x0b":
                # Ctrl-K
                # Clear all / cut AFTER cursor
                while cursor_position < len(input_symbols):
                    del input_symbols[cursor_position]
                sys.stdout.write("\033[0K")
            elif symbol[0] == "\x17":
                # Ctrl-W
                # delete the word BEFORE the cursor
                started_deleting = False
                while cursor_position > 0:
                    if input_symbols[cursor_position-1] == " " and started_deleting: break
                    # move cursor
                    started_deleting = True
                    sys.stdout.write("\b")
                    cursor_position -= 1
                    # erase from cursor to end of line
                    sys.stdout.write("\033[0K")
                    
                    # if there are characters after deleted character, print them again and move cursor back
                    del input_symbols[cursor_position]
                    for character in input_symbols[cursor_position:]:
                        sys.stdout.write(character)
                    for character in input_symbols[cursor_position:]:
                        sys.stdout.write("\b")
            elif symbol[0] == "\x0c":
                # Ctrl-L
                # Clear the screen
                sys.stdout.write("\033[K")
                for i in range(1, self.terminal_length+1):
                    print("")
                return
            elif symbol[0] == "\x1a":
                # Ctrl-Z
                # Same as Ctrl-C
                sys.stdout.write("\033[K")
                if self.current_level != "exec":
                    self.current_level = "exec"
                    self.prompt = f'{socket.gethostname()}#'
                    self.level_prefix = []
                print("")
                return
            elif symbol[0] == "\x14":
                # Ctrl-T
                # Swap the last two characters before the cursor
                if cursor_position > 1:
                    if len(input_symbols[:cursor_position]) > 1:
                        last_symbol = input_symbols[:cursor_position][-1]
                        penultimate_symbol = input_symbols[:cursor_position][-2]
                        new_input_symbols = input_symbols[:cursor_position][:-2]
                        # move cursor
                        sys.stdout.write("\b")
                        sys.stdout.write("\b")
                        # erase from cursor to end of line
                        sys.stdout.write("\033[0K")
                        # print swapped characters
                        new_input_symbols += last_symbol
                        sys.stdout.write(last_symbol)
                        new_input_symbols += penultimate_symbol
                        sys.stdout.write(penultimate_symbol)
                        # if there are characters after deleted character, print them again and move cursor back
                        for character in input_symbols[cursor_position:]:
                            new_input_symbols += character
                            sys.stdout.write(character)
                        for character in input_symbols[cursor_position:]:
                            sys.stdout.write("\b")
                        input_symbols = new_input_symbols
            elif symbol[0] == "\x7f" or symbol[0] == "\x08":
                # Backspace
                if cursor_position > 0:
                    # move cursor
                    sys.stdout.write("\b")
                    cursor_position -= 1
                    # erase from cursor to end of line
                    sys.stdout.write("\033[0K")
                    
                    # if there are characters after deleted character, print them again and move cursor back
                    del input_symbols[cursor_position]
                    for character in input_symbols[cursor_position:]:
                        sys.stdout.write(character)
                    for character in input_symbols[cursor_position:]:
                        sys.stdout.write("\b")
            elif symbol[0] == "\x1b":
                # arrow keys
                if len(symbol) < 2: 
                    print("")
                    return
                if symbol[2] == "D":
                    # left
                    if cursor_position > 0:
                        sys.stdout.write("\b")
                        cursor_position -= 1
                elif symbol[2] == "C":
                    # right
                    if cursor_position < len(input_symbols):
                        sys.stdout.write("\x1b[C")
                        cursor_position += 1
                elif symbol[2] == "A":
                    # up
                    # erase input and move to start of line
                    while cursor_position > 0:
                        sys.stdout.write("\b")
                        cursor_position -= 1
                    sys.stdout.write("\033[0K")
                    input_symbols = []
                    # retrieve historic command
                    if self.current_level == "exec":
                        if len(self.command_history_exec) > 0:
                            if len(self.command_history_exec) < self.historic_command_number_exec:
                                print(self.command_history_exec[0], end="")
                                input_symbols = list(self.command_history_exec[0])
                            else:
                                print(self.command_history_exec[-self.historic_command_number_exec], end="")
                                input_symbols = list(self.command_history_exec[-self.historic_command_number_exec])
                                self.historic_command_number_exec += 1
                            cursor_position = len(input_symbols)
                    else:
                        if len(self.command_history_config) > 0:
                            if len(self.command_history_config) < self.historic_command_number_config:
                                print(self.command_history_config[0], end="")
                                input_symbols = list(self.command_history_config[0])
                            else:
                                print(self.command_history_config[-self.historic_command_number_config], end="")
                                input_symbols = list(self.command_history_config[-self.historic_command_number_config])
                                self.historic_command_number_config += 1
                            cursor_position = len(input_symbols)                        
                elif symbol[2] == "B":
                    # down
                    # erase input and move to start of line
                    while cursor_position > 0:
                        sys.stdout.write("\b")
                        cursor_position -= 1
                    input_symbols = []
                    sys.stdout.write("\033[0K")
                    # retrieve previous historic command
                    if self.current_level == "exec":
                        if len(self.command_history_exec) > 0:
                            if self.historic_command_number_exec > 1:
                                self.historic_command_number_exec -= 1
                                if self.historic_command_number_exec == len(self.command_history_exec):
                                    self.historic_command_number_exec -= 1
                                print(self.command_history_exec[-self.historic_command_number_exec], end="")
                                input_symbols = list(self.command_history_exec[-self.historic_command_number_exec])
                            cursor_position = len(input_symbols)
                    else:
                        if len(self.command_history_config) > 0:
                            if self.historic_command_number_config > 1:
                                self.historic_command_number_config -= 1
                                if self.historic_command_number_config == len(self.command_history_config):
                                    self.historic_command_number_config -= 1
                                print(self.command_history_config[-self.historic_command_number_config], end="")
                                input_symbols = list(self.command_history_config[-self.historic_command_number_config])
                            cursor_position = len(input_symbols)
            else:
                if len(symbol) > 1:
                    # copy pasted input
                    for pasted_symbol in symbol:
                        if pasted_symbol == "\r" or pasted_symbol == "\n":
                            
                            #print("")
                            #print(input_symbols)
                            command_text = "".join(input_symbols)
                            command_text = command_text.strip()
                            if len(command_text) > 0:
                                if self.current_level == "exec":
                                    if len(self.command_history_exec) > 0:
                                        if command_text != self.command_history_exec[-1]:
                                            self.command_history_exec.append(command_text)
                                    else:
                                        self.command_history_exec.append(command_text)
                                else:
                                    if len(self.command_history_config) > 0:
                                        if command_text != self.command_history_config[-1]:
                                            self.command_history_config.append(command_text)
                                    else:
                                        self.command_history_config.append(command_text)
                            if self.current_level == "exec":
                                self.historic_command_number_exec = 1
                            else:
                                self.historic_command_number_config = 1
                            result, message = self.process_input_commands(command_text)
                            if message is None:
                                print("")
                            else:
                                print(f'\n{message}')
                            input_symbols = []
                            cursor_position = 0
                            print(self.prompt, end="")
                            
                        else:
                            sys.stdout.write(pasted_symbol)
                            input_symbols.insert(cursor_position, pasted_symbol)
                            cursor_position += 1
                else:
                    if symbol[0] not in allowed_characters:
                        continue
                    sys.stdout.write(symbol[0])
                    if len(input_symbols) > cursor_position:
                        for input_symbol in input_symbols[cursor_position:]:
                            sys.stdout.write(input_symbol)
                        for input_symbol in input_symbols[cursor_position:]:
                            sys.stdout.write("\b")
                    input_symbols.insert(cursor_position, symbol[0])
                    cursor_position += 1



    def run(self):
        print("### Welcome to the Bandwidth Sampler CLI! ###")
        while True:
            if self.exit == True: break
            self.read_input_line()


    





def main():

    cli_shell = CliShell()
    cli_shell.run()
    


if __name__ == "__main__":
    main()