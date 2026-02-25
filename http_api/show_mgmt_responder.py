#!/usr/bin/env python3

from pprint import pprint
from time import time
from datetime import timedelta


class ShowMgmtResponder:
    def __init__(self, mgmt_server):
        self.mgmt_server = mgmt_server


    def management_api_http(self):
        self.mgmt_server.logger.debug(f'Management-server show responder: Sending HTTP API info')
        management_api_http = {}
        management_api_http["enabled"] = False
        if not self.mgmt_server.http_config["shutdown"]:
            management_api_http["enabled"] = True
        management_api_http["running"] = self.mgmt_server.apis["http"].is_running()
        management_api_http["port"] = self.mgmt_server.http_config["port"]
        management_api_http["last_hit"] = self.mgmt_server.apis["http"].return_last_hit()
        management_api_http["hit_count"] = self.mgmt_server.apis["http"].return_hit_count()
        return management_api_http
    
    
    def management_api_https(self):
        self.mgmt_server.logger.debug(f'Management-server show responder: Sending HTTPS API info')
        management_api_https = {}
        management_api_https["enabled"] = False
        if not self.mgmt_server.https_config["shutdown"]:
            management_api_https["enabled"] = True
        management_api_https["running"] = self.mgmt_server.apis["https"].is_running()
        management_api_https["port"] = self.mgmt_server.https_config["port"]
        management_api_https["last_hit"] = self.mgmt_server.apis["https"].return_last_hit()
        management_api_https["hit_count"] = self.mgmt_server.apis["https"].return_hit_count()
        management_api_https["certificate"] = self.mgmt_server.apis["https"].return_tls_certificate()
        management_api_https["key"] = self.mgmt_server.apis["https"].return_tls_key()
        management_api_https["tls_version"] = "TLSv1.3"
        management_api_https["ciphers"] = self.mgmt_server.apis["https"].return_ciphers()
        return management_api_https
    

    RESPONDERS = {
        "management_api_http": management_api_http,
        "management_api_https": management_api_https
    }

    def get_response(self, query, command=None):
        self.mgmt_server.logger.debug(f'Management-server show responder: Received query {query}, arguments {command}')
        if query not in self.RESPONDERS.keys():
            return
        if command:
            return self.RESPONDERS[query](self, command)
        return self.RESPONDERS[query](self)