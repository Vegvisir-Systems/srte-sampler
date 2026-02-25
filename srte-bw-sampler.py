#!/usr/bin/env python3

from pprint import pprint
from multiprocessing import Process
from multiprocessing.managers import BaseManager
from eventlet import sleep
import socket
import logging.config
import copy
import json


from http_api.api_handler import ManagementServer
from config_manager.config_handler import ConfigHandler
from config_manager.config_handler import default_config
from config_manager.command_server import CommandServer
from config_manager.command_server import CompressedConcurrentRotatingFileHandler
from bgp.bgp_server import BgpServer
from sampler.sampling_server import SamplingServer

class CustomManager(BaseManager):
    pass

class HostnameFormatter(logging.Formatter):
    def format(self, record):
        record.hostname = socket.gethostname()
        return super().format(record)


default_logging_config = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "simple": {
            "format": "%(asctime)s %(hostname)s %(levelname)s: %(message)s",
        }
    },
    "handlers": {

        "log_to_file": {
            "class": "config_manager.command_server.CompressedConcurrentRotatingFileHandler",
            "formatter": "simple",
            "filename": "/var/log/srte_bw_sampler.log",
            "maxBytes": 20 * 1024 * 1024, 
            "backupCount": 10 
        }
    },
    "loggers": {
        "root": {"level": "INFO", "handlers": ["log_to_file"]}
    }
}


# DEBUG
# INFO
# WARNING
# ERROR / EXCEPTION
# CRITICAL



def main():


    logging.config.dictConfig(config=default_logging_config)
    formatter = HostnameFormatter(default_logging_config['formatters']['simple']['format'])
    for handler in logging.getLogger().handlers:
        handler.setFormatter(formatter)

    config_handler = ConfigHandler(default_config)
    config_handler.read_startup_config()
    
    syslog_config = config_handler.config["syslog"]
    new_logging_config = copy.deepcopy(default_logging_config)
    for host in syslog_config["hosts"]:
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

    CustomManager.register('BgpServer', BgpServer)
    CustomManager.register('ManagementServer', ManagementServer)
    CustomManager.register('SamplingServer', SamplingServer)


    with CustomManager() as manager:

        bgp_server = manager.BgpServer(config_handler.config["bgp"])
        mgmt_server = manager.ManagementServer(config_handler.config["management"])
        sampling_server = manager.SamplingServer(config_handler.config["sampling"],
                                                 config_handler.config["telemetry_profiles"],
                                                 config_handler.config["telemetry_clients"])
        command_server = CommandServer(config_handler, bgp_server, mgmt_server, sampling_server, default_logging_config)



        command_server_process = Process(target=command_server.run)
        bgp_server_process = Process(target=bgp_server.run)
        sampling_server_process = Process(target=sampling_server.run)
        mgmt_server_process = Process(target=mgmt_server.run)

        command_server_process.start()
        bgp_server_process.start()
        mgmt_server_process.start()
        sampling_server_process.start()


        command_server_process.join()
        bgp_server_process.join()
        mgmt_server_process.join()
        sampling_server_process.join()



if __name__ == "__main__":
    main()