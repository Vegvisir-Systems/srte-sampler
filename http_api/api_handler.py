#!/usr/bin/env python3

from pprint import pprint
import json
from flask import Flask, request, jsonify
from eventlet import GreenPool, listen, connect, greenthread, sleep
from eventlet.queue import Queue
from multiprocessing import Queue as mpQueue
from multiprocessing.managers import BaseManager
#from multiprocessing import Process
from multiprocessing.dummy import Process
from gevent.pywsgi import WSGIServer
from time import time
import pam
import ssl
import os
import msgpack
import socket
import logging
import logging.config
from datetime import datetime
import collections.abc

from .show_mgmt_responder import ShowMgmtResponder


class HostnameFormatter(logging.Formatter):
    def format(self, record):
        record.hostname = socket.gethostname()
        return super().format(record)
    


response_formats = ["json", "binary", "text"]

localhost_app = Flask(__name__)
@localhost_app.route('/command-api', methods=['POST'])
def index():
    credentials = request.authorization
    record = json.loads(request.data)

    localhost_app.config["update_counters"]()

    response = {}
    response["id"] = record["id"]
    response["jsonrpc"] = "2.0"
    if record["jsonrpc"] != "2.0":
        response["error"] = {}
        response["error"]["code"] = -32600
        response["error"]["message"] = "Invalid jsonrpc version"
        return jsonify(response)
    if record["method"] != "runCmds":
        response["error"] = {}
        response["error"]["code"] = -32601
        response["error"]["message"] = "Method not found"
        return jsonify(response)


    try:
        response_format = "json"
        version = 1
        if isinstance(record["params"], collections.abc.Mapping):
            version = record["params"]["version"]
            commands = record["params"]["cmds"]
            response_format = record["params"]["format"]
        else:
            version = record["params"][0]
            commands = record["params"][1]
            if len(record["params"]) > 2:
                response_format = record["params"][2]
    except KeyError:
        response["error"] = {}
        response["error"]["code"] = -32602
        response["error"]["message"] = "Invalid parameters"
        return jsonify(response)
    
    if version != 1:
        response["error"] = {}
        response["error"]["code"] = -32602
        response["error"]["message"] = "Invalid parameters"
        return jsonify(response)

    if type(commands) is not list or len(commands) == 0:
        response["error"] = {}
        response["error"]["code"] = -32602
        response["error"]["message"] = "Invalid parameters"
        return jsonify(response)

    if commands[0] == "enable":
        commands = commands[1:]

    if len(commands) == 0:
        response["error"] = {}
        response["error"]["code"] = -32602
        response["error"]["message"] = "Invalid parameters"
        return jsonify(response)


    if response_format not in response_formats:
        response["error"] = {}
        response["error"]["code"] = -32602
        response["error"]["message"] = "Invalid parameters"
        return jsonify(response)        
    
    if commands[0] == "enable":
        commands = commands[1:]

    
    if commands[0] == "authenticate":
        if not credentials:
            response["error"] = {}
            response["error"]["code"] = 10
            response["error"]["message"] = "Unauthorized"
            return jsonify(response)
        authorized = pam.authenticate(credentials["username"], credentials["password"])
        if not authorized:
            response["error"] = {}
            response["error"]["code"] = 10
            response["error"]["message"] = "Unauthorized"
            return jsonify(response)
        response["result"] = "Success"
        return jsonify(response)

    response = localhost_app.config["handler"](response, commands, response_format)

    return jsonify(response)


@localhost_app.route('/auth', methods=['POST'])
def authenticate():
    data = request.get_json()

    if not data or "username" not in data or "password" not in data:
        return jsonify({"message": "Invalid request"}), 400

    authorized = pam.authenticate(data["username"], data["password"])

    # Check credentials
    if authorized:
        return jsonify({"message": "Login successful", "status": "success"}), 200
    else:
        return jsonify({"message": "Invalid credentials", "status": "failure"}), 401


http_app = Flask(__name__)
@http_app.route('/command-api', methods=['POST'])
def index():
    
    credentials = request.authorization
    record = json.loads(request.data)
    
    http_app.config["update_counters"]()
     

    response = {}
    response["id"] = record["id"]
    response["jsonrpc"] = "2.0"
    if record["jsonrpc"] != "2.0":
        response["error"] = {}
        response["error"]["code"] = -32600
        response["error"]["message"] = "Invalid jsonrpc version"
        return jsonify(response)
    if record["method"] != "runCmds":
        response["error"] = {}
        response["error"]["code"] = -32601
        response["error"]["message"] = "Method not found"
        return jsonify(response)

    try:
        response_format = "json"
        version = 1
        if isinstance(record["params"], collections.abc.Mapping):
            version = record["params"]["version"]
            commands = record["params"]["cmds"]
            response_format = record["params"]["format"]
        else:
            version = record["params"][0]
            commands = record["params"][1]
            if len(record["params"]) > 2:
                response_format = record["params"][2]
    except KeyError:
        response["error"] = {}
        response["error"]["code"] = -32602
        response["error"]["message"] = "Invalid parameters"
        return jsonify(response)
    
    if version != 1:
        response["error"] = {}
        response["error"]["code"] = -32602
        response["error"]["message"] = "Invalid parameters"
        return jsonify(response)

    if type(commands) is not list or len(commands) == 0:
        response["error"] = {}
        response["error"]["code"] = -32602
        response["error"]["message"] = "Invalid parameters"
        return jsonify(response)

    enable = False
    if commands[0] == "enable":
        enable = True
        commands = commands[1:]

    if len(commands) == 0:
        response["error"] = {}
        response["error"]["code"] = -32602
        response["error"]["message"] = "Invalid parameters"
        return jsonify(response)


    if response_format not in response_formats:
        response["error"] = {}
        response["error"]["code"] = -32602
        response["error"]["message"] = "Invalid parameters"
        return jsonify(response)        
    

    if not credentials:
        response["error"] = {}
        response["error"]["code"] = 10
        response["error"]["message"] = "Unauthorized"
        return jsonify(response)
    authorized = pam.authenticate(credentials["username"], credentials["password"])
    if not authorized:
        response["error"] = {}
        response["error"]["code"] = 10
        response["error"]["message"] = "Unauthorized"
        return jsonify(response)
    

    response = https_app.config["handler"](response, commands, response_format)

    if enable:
        response["result"].insert(0, {})

    return jsonify(response)
 


https_app = Flask(__name__)
@https_app.route('/command-api', methods=['POST'])
def index():
    credentials = request.authorization
    record = json.loads(request.data)

    https_app.config["update_counters"]()

    pprint(record)

    response = {}
    response["id"] = record["id"]
    response["jsonrpc"] = "2.0"
    if record["jsonrpc"] != "2.0":
        response["error"] = {}
        response["error"]["code"] = -32600
        response["error"]["message"] = "Invalid jsonrpc version"
        return jsonify(response)
    if record["method"] != "runCmds":
        response["error"] = {}
        response["error"]["code"] = -32601
        response["error"]["message"] = "Method not found"
        return jsonify(response)
    

    try:
        response_format = "json"
        version = 1
        if isinstance(record["params"], collections.abc.Mapping):
            version = record["params"]["version"]
            commands = record["params"]["cmds"]
            response_format = record["params"]["format"]
        else:
            version = record["params"][0]
            commands = record["params"][1]
            if len(record["params"]) > 2:
                response_format = record["params"][2]
    except KeyError:
        response["error"] = {}
        response["error"]["code"] = -32602
        response["error"]["message"] = "Invalid parameters"
        return jsonify(response)
    
    if version != 1:
        response["error"] = {}
        response["error"]["code"] = -32602
        response["error"]["message"] = "Invalid parameters"
        return jsonify(response)

    if type(commands) is not list or len(commands) == 0:
        response["error"] = {}
        response["error"]["code"] = -32602
        response["error"]["message"] = "Invalid parameters"
        return jsonify(response)

    enable = False
    if commands[0] == "enable":
        enable = True
        commands = commands[1:]

    if len(commands) == 0:
        response["error"] = {}
        response["error"]["code"] = -32602
        response["error"]["message"] = "Invalid parameters"
        return jsonify(response)


    if response_format not in response_formats:
        response["error"] = {}
        response["error"]["code"] = -32602
        response["error"]["message"] = "Invalid parameters"
        return jsonify(response)        
    

    if not credentials:
        response["error"] = {}
        response["error"]["code"] = 10
        response["error"]["message"] = "Unauthorized"
        return jsonify(response)
    authorized = pam.authenticate(credentials["username"], credentials["password"])
    if not authorized:
        response["error"] = {}
        response["error"]["code"] = 10
        response["error"]["message"] = "Unauthorized"
        return jsonify(response)
    

    response = https_app.config["handler"](response, commands, response_format)

    if enable:
        response["result"].insert(0, {})


    return jsonify(response)



class HttpApi:
    def __init__(self, api_name, ip_address, port, logger):
        self.api_name = api_name
        self.ip_address = ip_address
        self.port = port
        self.logger = logger
        self.running = False
        self.queued_responses = Queue()
        self.answered_responses = []
        self.last_hit = int(time())
        self.hit_count = 0
        self.tls_cert = None
        self.tls_key = None
        self.tls_context = None
        self.apps = {
            "localhost": localhost_app,
            "http": http_app,
            "https": https_app
        }

    def dequeue_response(self):
        if self.queued_responses.qsize():
            return self.queued_responses.get()
        return
    
    def enqueue_answer(self, answer):
        self.logger.debug(f'Management-server {self.api_name}: Sending answer {answer}')
        # seems to work fine when only one response is allowed on the list, maybe just have a variable for one response
        self.answered_responses = []
        self.answered_responses.append(answer)

    def handle_request(self, response, request, response_format="json"):
        self.queued_responses.put((response, request, response_format))
        init_time = round(time()*1000)
        while True:
            if round(time()*1000) - init_time > 60000:
                response["error"] = {}
                response["error"]["code"] = -32000
                response["error"]["message"] = "API backend timeout"
                self.logger.error(f'Management-server {self.api_name}: API backend timeout in response to request {request}')
                return response

            for answered_response in self.answered_responses:
                if answered_response["id"] == response["id"]:
                    self.answered_responses.remove(answered_response)
                    return answered_response
                
    def update_counters(self):
        self.last_hit = int(time())
        self.hit_count += 1

    def return_last_hit(self):
        return self.last_hit
    
    def return_hit_count(self):
        return self.hit_count
        
    def set_port(self, port):
        self.port = port
    
    def set_tls_certificate(self, tls_cert):
        self.tls_cert = tls_cert

    def set_tls_key(self, tls_key):
        self.tls_key = tls_key

    def return_tls_certificate(self):
        return self.tls_cert
    
    def return_tls_key(self):
        return self.tls_key
    
    def return_ciphers(self):
        if not self.tls_context: return
        cipher_list = []
        for cipher in self.tls_context.get_ciphers():
            if cipher["protocol"] == "TLSv1.3":
                cipher_list.append(cipher["name"])
        return ":".join(cipher_list)


    def run(self):
        self.running = True
        app = self.apps[self.api_name]
        self.logger.debug(f'Management-server {self.api_name}: Starting API')
        app.config["handler"] = self.handle_request
        app.config["update_counters"] = self.update_counters
        if self.api_name == "https":
            if self.tls_cert and self.tls_key:
                try:
                    self.tls_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    self.tls_context.minimum_version = ssl.TLSVersion.TLSv1_3
                    self.tls_context.load_cert_chain(certfile=self.tls_cert, keyfile=self.tls_key)
                    self.tls_context.check_hostname=False
                    self.tls_context.verify_mode = ssl.CERT_OPTIONAL
                    self.api_server = WSGIServer((self.ip_address, self.port), app, ssl_context=self.tls_context)
                except Exception as e:
                    self.running = False
                    self.logger.error(f'Management-server {self.api_name}: Exception occurred when setting TLS context {e.__class__.__name__, e.args}')
                    return
            else:
                self.running = False
                return
        else:
            self.api_server = WSGIServer((self.ip_address, self.port), app)

        try:
            self.api_server.serve_forever()
        except Exception as e:
            self.running = False
            self.logger.error(f'Management-server {self.api_name}: Exception occurred when starting API {e.__class__.__name__, e.args}')

    def stop(self):
        self.running = False
        self.logger.debug(f'Management-server {self.api_name}: Stopping API')
        self.api_server.stop()

    def is_running(self):
        return self.running



    










class CustomManager(BaseManager):
    pass

class ManagementServer:
    def __init__(self, mgmt_config):
        CustomManager.register('HttpApi', HttpApi)
        manager = CustomManager()
        manager.start()
        self.logger = logging.getLogger("management_server")
        self.config_update_keepalive = 0
        
        self.http_config = mgmt_config["http-commands"]["http"]
        self.https_config = mgmt_config["http-commands"]["https"]
        self.localhost_api = manager.HttpApi("localhost", "127.0.0.1", 48777, self.logger)
        self.http_api = manager.HttpApi("http", "::0", self.http_config["port"], self.logger)
        self.https_api = manager.HttpApi("https", "::0", self.https_config["port"], self.logger)

    
        self.apis = {
            "localhost": self.localhost_api,
            "http": self.http_api,
            "https": self.https_api
        }

        self.api_processes = {
            "localhost": None,
            "http": None,
            "https": None            
        }

        self.responder = ShowMgmtResponder(self)
        self.config_updates = Queue()




    def start_api(self, api_name):
        if api_name not in self.apis.keys():
            self.logger.error(f'Management-server: Unknown api type {api_name}')
            return
        api_instance = self.apis[api_name]
        self.api_processes[api_name] = Process(target=api_instance.run)
        self.logger.info(f'Management-server: Starting API {api_name}')
        self.api_processes[api_name].start()

    def stop_api(self, api_name):
        if api_name not in self.apis.keys():
            self.logger.error(f'Management-server: Unknown api type {api_name}')
            return
        if self.api_processes[api_name]:
            self.logger.info(f'Management-server: Stopping API {api_name}')
            self.apis[api_name].stop()
            #if self.api_processes[api_name].is_alive():
            #    self.api_processes[api_name].terminate()


    def run(self):
        self.logger.info(f'Management-server: Starting management serer')
        config_updater = Process(target=self.update_config)
        config_updater.start()
        self.start_api("localhost")
        sleep(1)
        if not self.http_config["shutdown"]:
            self.start_api("http")
        sleep(1)
        if not self.https_config["shutdown"]:
            if "certificate" in self.https_config.keys() and "key" in self.https_config.keys():
                self.https_api.set_tls_certificate(self.https_config["certificate"])
                self.https_api.set_tls_key(self.https_config["key"])
                self.start_api("https")


    def get_query(self):
        for api_name, api in self.apis.items():
            if not api.is_running(): continue
            query = api.dequeue_response()
            if query:
                self.logger.debug(f'Management-server: Gor query {query} from API {api_name}')
                return api_name, query
        return None, None
    
    def enqueue_answer(self, api_name, answer):
        if api_name not in self.apis.keys():
            self.logger.error(f'Management-server: Unknown api type {api_name}')
            return
        if not self.apis[api_name].is_running(): return
        self.logger.debug(f'Management-server: Sending answer to API {api_name}')
        self.apis[api_name].enqueue_answer(answer)

    def show_command(self, query, command=None):
        return self.responder.get_response(query, command)
    

    def handle_http_shutdown(self, change_type, change_values, running_config):
        sleep(1)
        if change_type != "values_changed": return
        if change_values["new_value"] is True:
            self.http_config["shutdown"] = True
            if self.apis["http"].is_running():
                self.stop_api("http")
        elif change_values["new_value"] is False:
            self.http_config["shutdown"] = False
            if not self.apis["http"].is_running():
                self.start_api("http")

    def handle_http_port(self, change_type, change_values, running_config):
        if change_type != "values_changed": return
        self.http_config["port"] = change_values["new_value"]
        self.logger.debug(f'Management-server: Changing HTTP API port to {self.http_config["port"]}')
        if self.apis["http"].is_running():
            self.stop_api("http")
        self.apis["http"].set_port(self.http_config["port"])
        if self.http_config["shutdown"] is False:
            self.start_api("http")

    def handle_https_shutdown(self, change_type, change_values, running_config):
        sleep(1)
        if change_type != "values_changed": return
        if change_values["new_value"] is True:
            self.https_config["shutdown"] = True
            if self.apis["https"].is_running():
                self.stop_api("https")
        elif change_values["new_value"] is False:
            self.https_config["shutdown"] = False
            if not self.apis["https"].is_running():
                self.start_api("https")

    def handle_https_port(self, change_type, change_values, running_config):
        if change_type != "values_changed": return
        self.https_config["port"] = change_values["new_value"]
        self.logger.debug(f'Management-server: Changing HTTPS API port to {self.https_config["port"]}')
        if self.apis["https"].is_running():
            self.stop_api("https")
        self.apis["https"].set_port(self.https_config["port"])
        if self.https_config["shutdown"] is False:
            self.start_api("https")

    def handle_https_certificate(self, change_type, change_values, running_config):
        # without sleep it throws exception ('OSError', (98, 'Address already in use')) when both cert and key are changed
        sleep(1)
        self.https_config["certificate"] = change_values["new_value"]
        self.logger.debug(f'Management-server: Changing HTTPS API certificate to to {self.https_config["certificate"]}')
        if self.apis["https"].is_running():
            self.stop_api("https")
        self.https_api.set_tls_certificate(self.https_config["certificate"])
        if self.https_config["shutdown"] is False:
            self.start_api("https")
                
    def handle_https_key(self, change_type, change_values, running_config):
        sleep(1)
        self.https_config["key"] = change_values["new_value"]
        self.logger.debug(f'Management-server: Changing HTTPS API key to to {self.https_config["key"]}')
        if self.apis["https"].is_running():
            self.stop_api("https")
        self.https_api.set_tls_key(self.https_config["key"])
        if self.https_config["shutdown"] is False:
            self.start_api("https")                
        
    HTTP_CHANGES = {
        "shutdown": handle_http_shutdown,
        "port": handle_http_port
    }

    HTTPS_CHANGES = {
        "shutdown": handle_https_shutdown,
        "port": handle_https_port,
        "certificate": handle_https_certificate,
        "key": handle_https_key
    }    

    def handle_http_changes(self, change_type, change_path, change_values, running_config):
        if change_path[0] in self.HTTP_CHANGES.keys():
            change_handler = self.HTTP_CHANGES[change_path[0]]
            change_handler(self, change_type, change_values, running_config)


    def handle_https_changes(self, change_type, change_path, change_values, running_config):
        if change_path[0] in self.HTTPS_CHANGES.keys():
            change_handler = self.HTTPS_CHANGES[change_path[0]]
            change_handler(self, change_type, change_values, running_config)

    HTTP_API_CONFIG_CHANGES = {
        "http": handle_http_changes,
        "https": handle_https_changes
    }
    
    def handle_http_api_changes(self, change_type, change_path, change_values, running_config):
        if change_path[0] in self.HTTP_API_CONFIG_CHANGES.keys():
            change_handler = self.HTTP_API_CONFIG_CHANGES[change_path[0]]
            change_handler(self, change_type, change_path[1:], change_values, running_config)

    def handle_gnmi_changes(self, change_type, change_path, change_values, running_config):
        pass

    API_CONFIG_CHANGES = {
        "http-commands": handle_http_api_changes,
        "gnmi": handle_gnmi_changes
    }

    def return_keepalives(self):
        return {"config_update_keepalive": self.config_update_keepalive}
    

    def add_config_changes(self, change_type, change_server, changes_list, running_config=None):
        for change_item in changes_list:
            self.logger.debug(f'Management-server: Queuing config change {change_type}, {change_item[0]}, {change_item[1]}')
            self.config_updates.put((change_type, change_server, change_item[0], change_item[1], running_config))


    def update_config(self):
        while True:
            sleep(2)
            self.config_update_keepalive = int(time())
            if not self.config_updates.qsize(): continue
            init_time = round(time()*1000)
            while self.config_updates.qsize():
                self.logger.debug(f'Management-server: Fetching config updates')
                if round(time()*1000) - init_time > 200: break
                change_type, change_server, change_path_processed, change_values, running_config = self.config_updates.get()
                if change_server != "management": break
                if change_path_processed[0] in self.API_CONFIG_CHANGES.keys():
                    change_handler = self.API_CONFIG_CHANGES[change_path_processed[0]]
                    try:
                        change_handler(self, change_type, change_path_processed[1:], change_values, running_config)
                    except Exception as e:
                        self.logger.exception(f'Management-server: Unable to process config change for {change_server}, {change_type}, {change_path_processed}, {change_values}')

    def update_logging_config(self, new_logging_config):
        self.logger.debug(f'Management-server: Updating logging config')
        logging.config.dictConfig(config=new_logging_config)
        formatter = HostnameFormatter(new_logging_config['formatters']['simple']['format'])
        for handler in logging.getLogger().handlers:
            handler.setFormatter(formatter)

    def debug_api(self, command=None, undebug=False):
        if undebug:
            self.logger.warning(f'Management-server: Disabling debug for API')
            self.logger.setLevel(logging.INFO)
            return {'warnings': ['Disabled debugging for API']}
        self.logger.warning(f'Management-server: Enabling debug for API')
        self.logger.setLevel(logging.DEBUG)
        return {'warnings': ['Enabled debugging for API']}

    DEBUG_RESPONDERS = {
        "api": debug_api,
    }

    def debug_command(self, query, command=None, undebug=False):
        self.logger.debug(f'Management-server: Received debug command query {query}, arguments {command}')
        if query not in self.DEBUG_RESPONDERS.keys(): return
        return self.DEBUG_RESPONDERS[query](self, command, undebug=undebug)    