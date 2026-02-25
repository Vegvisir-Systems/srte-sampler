#!/usr/bin/env python3

from pprint import pprint
from eventlet import GreenPool, listen, connect, greenthread, sleep, semaphore
from eventlet.queue import Queue
import socket
import struct
import json
from pyroute2 import IPRoute
from time import time, time_ns
import logging
import logging.config
import ipaddress
from deepdiff import DeepDiff
from pygnmi.client import gNMIclient
import threading
import re
import sqlite3
import os
from datetime import datetime

from .sampling_defaults import *
from .sampling_mocks import SamplingMock
from .show_sampling_responder import ShowSamplingResponder

def ns_to_datetime_str(ns: int) -> str:
    return datetime.fromtimestamp(ns / 1e9).strftime("%Y-%m-%d %H:%M:%S")

class HostnameFormatter(logging.Formatter):
    def format(self, record):
        record.hostname = socket.gethostname()
        return super().format(record)


class GnmiSampler:
    def __init__(self, client_ip, client_settings, gnmi_streaming_queue, sampling_interval):
        self.client_ip = client_ip
        self.client_settings = client_settings
        self.gnmi_streaming_queue = gnmi_streaming_queue
        self.sampling_interval = sampling_interval
        self.router_id = None
        #self.worker_queue = Queue()
        self.eventlets = []
        self.pool = GreenPool()
        self.logger = logging.getLogger(f'sampling_{self.client_ip}')
        self.running = False
        self.mock_object = None
        if MOCK_ENABLED:
            self.mock_object = SamplingMock()
        self.last_read_time = 0
        self.junos_collector_thread = None
        self.junos_stop_event = threading.Event()
        

    ### EOS HANDLING BLOCK


    @staticmethod
    def parse_eos_router_id(data):
        """
        data: EOS gNMI GET JSON (json_ietf)
        returns: router-id string or None
        """

        for notif in data.get("notification", []):
            for upd in notif.get("update", []):
                path = upd.get("path", "")
                if not path.endswith("/bgp"):
                    continue

                val = upd.get("val", {})
                if not isinstance(val, dict):
                    continue

                global_bgp = val.get("openconfig-network-instance:global", {})
                if not isinstance(global_bgp, dict):
                    continue

                # Prefer state, fall back to config
                state = global_bgp.get("state", {})
                if isinstance(state, dict) and "router-id" in state:
                    return state["router-id"]

                config = global_bgp.get("config", {})
                if isinstance(config, dict) and "router-id" in config:
                    return config["router-id"]

        return None


    @staticmethod
    def parse_eos_srte_policy(data):
        """
        data: EOS gNMI GET JSON (json_ietf)
        returns: list of dicts (one per SR-TE policy)
        """

        results = []

        for notif in data.get("notification", []):
            device_ts = notif.get("timestamp")

            for upd in notif.get("update", []):
                val = upd.get("val", {})

                policies = val.get("openconfig-network-instance:te-policy", [])
                if not isinstance(policies, list):
                    continue

                for pol in policies:
                    # Color / endpoint can be in either place depending on EOS version
                    state = pol.get("state", {})

                    color = state.get("color", pol.get("color"))
                    endpoint = state.get("endpoint", pol.get("endpoint"))

                    if color is None or endpoint is None:
                        continue  # should not happen, but be defensive

                    # Counters are OPTIONAL on EOS
                    counters = state.get("counters", {})
                    out_octets = int(counters.get("out-octets", 0))

                    results.append({
                        "local_timestamp": time_ns(),
                        "device_timestamp": device_ts,
                        "color": int(color),
                        "endpoint": endpoint,
                        "out_octets": out_octets,
                    })

        return results


    def get_eos_router_id(self, sampler):
        path = [
            "/network-instances/network-instance[name=default]/protocols/protocol[identifier=BGP]/bgp"
        ]
        data = sampler.get(path=path, encoding="json_ietf")
        return self.parse_eos_router_id(data)


    def get_eos_counters(self, sampler):
        path = [
            "/network-instances/network-instance[name=default]/segment-routing/te-policies"
        ]
        return sampler.get(path=path, encoding="json_ietf")


    def run_eos_client(self):
        with gNMIclient(
            target=(self.client_ip, self.client_settings["port"]),
            username=self.client_settings["username"],
            password=self.client_settings["password"],
            insecure=True
        ) as sampler:

            while True:
                sleep(0.1)
                if (int(time()) - self.sampling_interval) < self.last_read_time:
                    continue

                self.logger.debug(f"Sampling client {self.client_ip}: Starting EOS telemetry collector")
                self.last_read_time = int(time())

                try:
                    self.router_id = self.get_eos_router_id(sampler)
                    update = self.get_eos_counters(sampler)
                    policy_list = self.parse_eos_srte_policy(update)

                    if policy_list and self.router_id:
                        for policy_info in policy_list:
                            policy_info["router_id"] = self.router_id

                            if self.mock_object:
                                policy_info["out_octets"] = (
                                    self.mock_object.return_srte_counter(
                                        policy_info, self.sampling_interval
                                    )
                                )
                            self.gnmi_streaming_queue.put(policy_info)
                except Exception as e:
                    self.logger.error(f"Sampling client {self.client_ip}: Exception when attempting to collect SR-TE counters: {e}")


    ### XR HANDLING BLOCK


    @staticmethod
    def parse_iosxr_router_id(data):
        """
        xr_reading: dict returned by IOS-XR gNMI GET (json_ietf)
        returns: router-id string or None
        """

        for notif in data.get("notification", []):
            for upd in notif.get("update", []):
                path = upd.get("path", "")
                if path.endswith("/bgp/global/state/router-id"):
                    return upd.get("val")

        return None


    @staticmethod
    def parse_iosxr_srte_policy(data):
        """
        data: dict parsed from IOS-XR gNMI GET JSON output
        returns: list of dicts with IPv4 + IPv6 counters summed
        """
        SR_IF_RE = re.compile(
            r"interfaces/interface\[name=sr-srte_c_(?P<color>\d+)_ep_(?P<endpoint>[^\]]+)\]"
        )
        # (timestamp, color, endpoint) -> aggregated result
        agg = {}

        for notif in data.get("notification", []):
            timestamp = notif.get("timestamp")

            for upd in notif.get("update", []):
                path = upd.get("path", "")
                val = upd.get("val", {})

                m = SR_IF_RE.search(path)
                if not m:
                    continue

                counters = val.get("counters")
                if not counters:
                    continue

                color = int(m.group("color"))
                endpoint = m.group("endpoint")
                out_octets = int(counters.get("out-octets", 0))

                key = (timestamp, color, endpoint)

                if key not in agg:
                    agg[key] = {
                        "local_timestamp": time_ns(),
                        "device_timestamp": timestamp,
                        "color": color,
                        "endpoint": endpoint,
                        "out_octets": 0,
                    }

                # IPv4 + IPv6 summed here
                agg[key]["out_octets"] += out_octets

        return list(agg.values())


    def get_iosxr_router_id(self, sampler):
        xr_router_id_path = [
            "/network-instances/network-instance/protocols/protocol[identifier=BGP][name=default]/bgp/global/state/router-id"
        ]
        return self.parse_iosxr_router_id(sampler.get(path=xr_router_id_path, encoding='json_ietf'))


    def get_iosxr_counters(self, sampler):

        xr_counters_path = [
            "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv4/state",
            "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv6/state"
        ]
        return sampler.get(path=xr_counters_path, encoding='json_ietf')


    def run_iosxr_client(self):
        with gNMIclient(target=(self.client_ip, self.client_settings["port"]),
                        username=self.client_settings["username"], password=self.client_settings["password"], insecure=True) as sampler:
            
            while True:
                sleep(0.1)
                if (int(time()) - self.sampling_interval) < self.last_read_time: continue
                self.logger.debug(f'Sampling client {self.client_ip}: Starting IOS-XR telemetry collector')
                self.last_read_time = int(time())
                try:
                    self.router_id = self.get_iosxr_router_id(sampler)
                    update = self.get_iosxr_counters(sampler)
                    policy_list = self.parse_iosxr_srte_policy(update)
                    if policy_list:
                        if self.router_id:
                            for policy_info in policy_list:          
                                policy_info["router_id"] = self.router_id
                                if self.mock_object:
                                    policy_info["out_octets"] = self.mock_object.return_srte_counter(policy_info, self.sampling_interval)
                                self.gnmi_streaming_queue.put(policy_info)
                except:
                    pass
                

    ### JUNOS HANDLING BLOCK ###

    
    @staticmethod
    def parse_junos_router_id(resp):
        if not resp.HasField("update"):
            return None

        notif = resp.update

        for u in notif.update:
            path = [e.name for e in u.path.elem]
            if path == ["bgp", "global", "state", "router-id"]:
                return u.val.json_val.decode().strip('"')

        return None
    

    @staticmethod
    def parse_junos_srte_policy(resp):
        """
        resp: SubscribeResponse object from pygnmi
        returns: dict or None
        """

        # Ignore non-update messages
        if not resp.HasField("update"):
            return None

        notif = resp.update

        result = {
            "local_timestamp": time_ns(),
            "device_timestamp": notif.timestamp,
            "router_id": None,
            "endpoint": None,
            "color": None,
            "out_octets": None,
        }

        for elem in notif.prefix.elem:
            if elem.name == "sr-te-ip-policy":
                result["endpoint"] = elem.key.get("to-address")
                result["color"] = int(elem.key.get("color"))

        for u in notif.update:
            if u.path.elem and u.path.elem[0].name == "bytes":
                result["out_octets"] = int(u.val.json_val.decode())
        if result["endpoint"] is None or result["out_octets"] is None:
            return None

        return result


    def junos_router_id_worker(self):
        subscription_request = {
            "subscription": [
                {
                    "path": "/network-instances/network-instance/"
                            "protocols/protocol[identifier=BGP]/bgp/",
                    "mode": "sample",
                    "sample_interval": 300_000_000_000,
                }
            ],
            "mode": "stream",
        }
        try:
            with gNMIclient(
                target=(self.client_ip, self.client_settings["port"]),
                username=self.client_settings["username"],
                password=self.client_settings["password"],
                insecure=True,
            ) as sampler:

                for resp in sampler.subscribe(subscription_request):
                    rid = self.parse_junos_router_id(resp)
                    if rid:
                        self.router_id = rid
        except:
            pass


    def junos_srte_sample_once(self, stop_event):
        subscription_request = {
            "subscription": [
                {
                    "path": "/mpls/signaling-protocols/segment-routing/",
                    "mode": "sample",
                    "sample_interval": 60_000_000_000,  # irrelevant, we exit early
                }
            ],
            "mode": "stream",
        }
        try:
            with gNMIclient(
                target=(self.client_ip, self.client_settings["port"]),
                username=self.client_settings["username"],
                password=self.client_settings["password"],
                insecure=True,
            ) as sampler:

                last_rx = time()

                for resp in sampler.subscribe(subscription_request):
                    if stop_event.is_set():
                        break
                    policy_info = self.parse_junos_srte_policy(resp)
                    if policy_info and self.router_id:
                        last_rx = time()
                        policy_info["router_id"] = self.router_id

                        if self.mock_object:
                            policy_info["out_octets"] = (
                                self.mock_object.return_srte_counter(
                                    policy_info, self.sampling_interval
                                )
                            )
                        self.gnmi_streaming_queue.put(policy_info)

                    # stop after quiet period (no updates)
                    if time() - last_rx > 0.5:
                        break
        except:
            pass


    def run_junos_client(self):
        # start router-id worker ONCE
        self.logger.debug(f'Sampling client {self.client_ip}: Starting JUNOS router-id collector')
        t_rid = threading.Thread(
            target=self.junos_router_id_worker,
            daemon=True,
        )
        t_rid.start()

        while True:
            sleep(0.1)
            if (int(time()) - self.sampling_interval) < self.last_read_time: continue
            self.logger.debug(f'Sampling client {self.client_ip}: Starting JUNOS telemetry collector')
            self.last_read_time = int(time())
            try:
                #self.junos_stop_event.set()
                t_collector = threading.Thread(
                    target=self.junos_srte_sample_once,
                    args=(self.junos_stop_event,),
                    daemon=True,
                )
                t_collector.start()
            except:
                pass

    
    SUPPORTED_OS = {
        "eos": run_eos_client,
        "iosxr": run_iosxr_client,
        "junos": run_junos_client
    }


    def run(self):
        if not self.client_settings["valid_config"]:
            self.logger.error(f'Sampling client {self.client_ip}: Invalid config - unable to start thread')
            return
        if self.client_settings["os"] not in self.SUPPORTED_OS.keys():
            self.logger.error(f'Sampling client {self.client_ip}: OS {self.client_settings["os"]} not supported - unable to start thread')
            return
        self.running = True
        self.logger.debug(f'Sampling client {self.client_ip}: Starting sampling thread')
        self.SUPPORTED_OS[self.client_settings["os"]](self)





class SamplingServer:
    def __init__(self, sampling_options, telemetry_profiles, telemetry_clients):
        self.sampling_options = sampling_options
        self.telemetry_profiles = telemetry_profiles
        self.telemetry_clients = telemetry_clients
        self.responder = ShowSamplingResponder(self)
        self.processed_clients = {} # validated client config with profile attached
        self.samplers = {} # GnmiSampler objects
        self.running_samplers = {} # running sampler threads
        self.running = False
        self.config_updates = Queue()
        self.pool = GreenPool()
        self.gnmi_streaming_queue = Queue()
        self.sampling_to_bgp_queue = Queue()
        self.logger = logging.getLogger("sampling_server")
        self.config_update_keepalive = 0
        self.gnmi_streaming_keepalive = 0
        self.calculate_bandwidth_keepalive = 0
        self.cleanup_old_policies_keepalive = 0
        self.sampling_db_path = sampling_options["sampling_database"]
        if self.sampling_db_path is None:
            self.sampling_db_path = DEFAULT_DB_PATH
        self.db_write_conn = None
        self.actual_adjust_interval = sampling_options["adjust_interval"]
        if self.actual_adjust_interval < sampling_options["sampling_interval"] * 6:
            self.actual_adjust_interval = sampling_options["sampling_interval"] * 6
        self.last_adjust_time = 0
        self.sampled_policies = {}

        
    def process_client(self, client_ip, profile_name):
        self.logger.debug(f'Sampling-server: Processing telemetry config for client {client_ip}')
        client_dict = {
            'valid_config': False,
            'invalid_config_reason': None,
            'os': None,
            'port': None,
            'auth': None,
            'username': None,
            'password': None
        }
        profile_found = False
        for configured_profile in self.telemetry_profiles:
            configured_profile_name = configured_profile.get("profile_name", None)
            if not configured_profile_name: continue
            if configured_profile_name == profile_name:
                profile_found = True
                os = configured_profile.get("os", None)
                if not os:
                    self.logger.debug(f'Sampling-server: Config for client {client_ip} invalid - OS not configured')
                    client_dict["valid_config"] = False
                    client_dict["invalid_config_reason"] = "OS not configured"
                    break
                client_dict["os"] = os

                port = configured_profile.get("port", None)
                if not port:
                    self.logger.debug(f'Sampling-server: Config for client {client_ip} invalid - port not configured')
                    client_dict["valid_config"] = False
                    client_dict["invalid_config_reason"] = "port not configured"
                    break
                client_dict["port"] = port

                auth = configured_profile.get("auth", None)
                if not auth:
                    self.logger.debug(f'Sampling-server: Config for client {client_ip} invalid - auth not configured')
                    client_dict["valid_config"] = False
                    client_dict["invalid_config_reason"] = "auth not configured"
                    break
                client_dict["auth"] = auth

                # leaving this here until implementing certificate auth
                if auth == "certificate":
                    self.logger.debug(f'Sampling-server: Config for client {client_ip} invalid - cert auth not implemented yet')
                    client_dict["valid_config"] = False
                    client_dict["invalid_config_reason"] = "cert auth not implemented yet"
                    break

                username = configured_profile.get("username", None)
                if not username:
                    self.logger.debug(f'Sampling-server: Config for client {client_ip} invalid - username not configured')
                    client_dict["valid_config"] = False
                    client_dict["invalid_config_reason"] = "username not configured"
                    break
                client_dict["username"] = username

                password = configured_profile.get("password", None)
                if not password:
                    self.logger.debug(f'Sampling-server: Config for client {client_ip} invalid - password not configured')
                    client_dict["valid_config"] = False
                    client_dict["invalid_config_reason"] = "password not configured"
                    break
                client_dict["password"] = password
                
                client_dict["valid_config"] = True
                client_dict["invalid_config_reason"] = None
                break

        if not profile_found:
            self.logger.debug(f'Sampling-server: Config for client {client_ip} invalid - no profile {profile_name}')
            client_dict["valid_config"] = False
            client_dict["invalid_config_reason"] = "Profile not found"
            return

        if not client_dict["valid_config"]: return

        if client_ip not in self.processed_clients.keys():
            self.processed_clients[client_ip] = client_dict
            return
        if not DeepDiff(self.processed_clients[client_ip], client_dict, ignore_order=True):
            return
        self.processed_clients[client_ip] = client_dict


    def process_all_clients(self):
        self.logger.info(f'Sampling-server: Processing telemetry clients config')
        for configured_client_group in self.telemetry_clients:
            profile_name = configured_client_group.get("profile", None)
            if not profile_name:
                self.logger.debug(f'Sampling-server: Client group {configured_client_group["client_group"]} has no profile, skipping')
                continue
            client_list = configured_client_group.get("clients", [])
            for client in client_list:
                self.process_client(client["remote_ip"], profile_name)



    def add_config_changes(self, change_type, change_server, changes_list, running_config=None):
        for change_item in changes_list:
            self.logger.debug(f'Sampling-server: Queuing config change {change_type}, {change_item[0]}, {change_item[1]}')
            self.config_updates.put((change_type, change_server, change_item[0], change_item[1], running_config))


    def update_config(self):
        while True:
            sleep(2)
            self.config_update_keepalive = int(time())
            if not self.config_updates.qsize(): continue
            init_time = round(time()*1000)
            while self.config_updates.qsize():
                self.logger.debug(f'Sampling-server: Fetching config updates')
                if round(time()*1000) - init_time > 200: break
                change_type, change_server, change_path_processed, change_values, running_config = self.config_updates.get()
                print("------")
                print(change_type)
                print(change_server)
                print(change_path_processed)
                print(change_values)
                print("------")
                try:
                    if change_server == "telemetry_profiles":
                        self.stop_samplers()
                        self.telemetry_profiles = running_config["telemetry_profiles"]
                        self.samplers = {}
                        self.running_samplers = {}
                        self.process_all_clients()
                        for client_ip, client_settings in self.processed_clients.items():
                            sampler = GnmiSampler(client_ip, client_settings, self.gnmi_streaming_queue, self.sampling_options["sampling_interval"])
                            self.samplers[client_ip] = sampler
                        self.start_samplers()
                    # client add: process this one client and start thread
                    # client remove: remove this one client and remove thread
                    # client profile change: reprocess the entire client group and restart relevant threads
                    # for now just restarting all clients
                    elif change_server == "telemetry_clients":
                        self.stop_samplers()
                        self.telemetry_clients = running_config["telemetry_clients"]
                        self.processed_clients = {}
                        self.samplers = {}
                        self.running_samplers = {}
                        self.process_all_clients()
                        for client_ip, client_settings in self.processed_clients.items():
                            sampler = GnmiSampler(client_ip, client_settings, self.gnmi_streaming_queue, self.sampling_options["sampling_interval"])
                            self.samplers[client_ip] = sampler
                        self.start_samplers()
                    # sampling interval change: restart all threads
                    # sampling database change: TBD
                    # adjust settings change: TBD
                    # for now just restart everything
                    elif change_server == "sampling":
                        self.stop_samplers()
                        self.samplers = {}
                        self.running_samplers = {}
                        self.sampling_db_path = running_config["sampling"]["sampling_database"]
                        if self.sampling_db_path is None:
                            self.sampling_db_path = DEFAULT_DB_PATH
                        self.db_write_conn = None
                        self.actual_adjust_interval = running_config["sampling"]["adjust_interval"]
                        if self.actual_adjust_interval < running_config["sampling"]["sampling_interval"] * 6:
                            self.actual_adjust_interval = running_config["sampling"]["sampling_interval"] * 6
                        self.process_all_clients()
                        for client_ip, client_settings in self.processed_clients.items():
                            sampler = GnmiSampler(client_ip, client_settings, self.gnmi_streaming_queue, self.sampling_options["sampling_interval"])
                            self.samplers[client_ip] = sampler
                        self.start_samplers()
                except:
                    self.logger.exception(f'Sampling-server: Unable to process config change for {change_server}, {change_type}, {change_path_processed}, {change_values}')



    @staticmethod
    def try_init_db(db_path, logger, retry_interval=5):
        logger.debug(f'Sampling-server: Trying to init database')
        try:
            os.makedirs(os.path.dirname(db_path), exist_ok=True)

            conn = sqlite3.connect(
                db_path,
                timeout=2,
                check_same_thread=False,
                isolation_level=None
            )

            cur = conn.cursor()
            cur.execute("""
            CREATE TABLE IF NOT EXISTS srte_counters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                router_id TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                color INTEGER NOT NULL,
                out_octets INTEGER NOT NULL,
                device_timestamp INTEGER NOT NULL,
                local_timestamp INTEGER NOT NULL
            )
            """)

            cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_srte_lookup
            ON srte_counters (router_id, endpoint, color, device_timestamp)
            """)

            conn.commit()
            logger.debug(f'Sampling-server: Connected to database at {db_path}')
            return conn

        except Exception as e:
            logger.critical(f'Sampling-server: Unable to init database file {db_path}')
            sleep(retry_interval)
            return None
    

    def handle_streaming_updates(self):
        cur = None
        backlog = [] 

        while True:
            sleep(1)
            self.gnmi_streaming_keepalive = int(time())

            # Attempt DB connection if not connected
            if self.db_write_conn is None:
                self.db_write_conn = self.try_init_db(self.sampling_db_path, self.logger)
                if self.db_write_conn:
                    cur = self.db_write_conn.cursor()
                    # flush backlog
                    if backlog:
                        self.logger.info(f'Sampling-server: Flushing {len(backlog)} buffered records')
                        try:
                            cur.executemany("""
                                INSERT INTO srte_counters (
                                    router_id, endpoint, color,
                                    out_octets, device_timestamp, local_timestamp
                                ) VALUES (?, ?, ?, ?, ?, ?)
                            """, backlog)
                            self.db_write_conn.commit()
                            backlog.clear()
                        except Exception as e:
                            self.logger.error(f'Sampling-server: Backlog flush failed: {e}')
                            self.db_write_conn = None
                            cur = None
                            continue

            batch = []
            start_ms = round(time() * 1000)

            while self.gnmi_streaming_queue.qsize():
                if round(time() * 1000) - start_ms > 200:
                    break

                policy_info = self.gnmi_streaming_queue.get()

                row = (
                    policy_info["router_id"],
                    policy_info["endpoint"],
                    policy_info["color"],
                    policy_info["out_octets"],
                    policy_info["device_timestamp"],
                    policy_info["local_timestamp"],
                )

                batch.append(row)

                if len(batch) >= BATCH_SIZE:
                    if self.db_write_conn:
                        try:
                            cur.executemany("""
                                INSERT INTO srte_counters (
                                    router_id, endpoint, color,
                                    out_octets, device_timestamp, local_timestamp
                                ) VALUES (?, ?, ?, ?, ?, ?)
                            """, batch)
                            self.db_write_conn.commit()
                        except Exception as e:
                            self.logger.error(f'Sampling-server: DB write failed: {e}')
                            self.db_write_conn = None
                            cur = None
                            backlog.extend(batch)
                    else:
                        backlog.extend(batch)

                    batch.clear()

            # Final flush
            if batch:
                if self.db_write_conn:
                    try:
                        cur.executemany("""
                            INSERT INTO srte_counters (
                                router_id, endpoint, color,
                                out_octets, device_timestamp, local_timestamp
                            ) VALUES (?, ?, ?, ?, ?, ?)
                        """, batch)
                        self.db_write_conn.commit()
                    except Exception as e:
                        self.logger.error(f'Sampling-server: DB write failed: {e}')
                        self.db_write_conn = None
                        cur = None
                        backlog.extend(batch)
                else:
                    backlog.extend(batch)

            # prevent memory blow-up
            if len(backlog) > MAX_BACKLOG:
                self.logger.error(f'Sampling-server: Backlog full, dropping old samples')
                backlog = backlog[-MAX_BACKLOG:]


    @staticmethod
    def exceeds_adjust_threshold(old_bps, new_bps, threshold_pct):
        """
        Returns True if new_bps differs from old_bps by >= threshold_pct percent
        """

        if old_bps <= 0:
            # no baseline → always adjust
            return True

        delta_pct = abs(new_bps - old_bps) / old_bps * 100
        return delta_pct >= threshold_pct


    def calculate_average_bandwidth(self):
        while True:
            sleep(1)
            self.calculate_bandwidth_keepalive = int(time())
            if (int(time()) - self.actual_adjust_interval) < self.last_adjust_time: continue
            self.logger.debug(f'Sampling-server: Calculating bandwidth rate for policies...')
            self.last_adjust_time = int(time())
            WINDOW_NS = self.actual_adjust_interval * 1_000_000_000
            MIN_SAMPLES = self.actual_adjust_interval // self.sampling_options["sampling_interval"]
            try:
                conn = sqlite3.connect(self.sampling_db_path)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()

                # Step 1: get all distinct policies
                #cur.execute("""
                #    SELECT DISTINCT router_id, endpoint, color
                #    FROM srte_counters
                #""")
                now_ns = time_ns()
                recent_cutoff = now_ns - WINDOW_NS   # only policies active in current window

                cur.execute("""
                    SELECT DISTINCT router_id, endpoint, color
                    FROM srte_counters
                    WHERE local_timestamp >= ?
                """, (recent_cutoff,))


                
                policies = cur.fetchall()
                results = []

                for p in policies:
                    router_id = p["router_id"]
                    endpoint = p["endpoint"]
                    color = p["color"]
                    cur.execute("""
                        SELECT MAX(local_timestamp) AS latest_ts
                        FROM srte_counters
                        WHERE router_id = ?
                        AND endpoint = ?
                        AND color = ?
                    """, (router_id, endpoint, color))

                    row = cur.fetchone()
                    if not row or row["latest_ts"] is None:
                        continue

                    latest_ts = row["latest_ts"]
                    window_start = latest_ts - WINDOW_NS
                    # Step 2: fetch samples for last 60s
                    cur.execute("""
                        SELECT local_timestamp, out_octets
                        FROM srte_counters
                        WHERE router_id = ?
                        AND endpoint = ?
                        AND color = ?
                        AND local_timestamp >= ?
                        ORDER BY local_timestamp ASC
                    """, (router_id, endpoint, color, window_start))

                    rows = cur.fetchall()

                    # Step 3: ensure enough samples
                    if len(rows) < MIN_SAMPLES:
                        continue  # not enough data yet

                    first = rows[0]
                    last = rows[-1]

                    time_delta_ns = last["local_timestamp"] - first["local_timestamp"]
                    if time_delta_ns <= 0:
                        continue

                    byte_delta = last["out_octets"] - first["out_octets"]
                    if byte_delta < 0:
                        continue  # counter reset

                    # Step 4: compute bandwidth
                    time_delta_sec = time_delta_ns / 1e9
                    bps = int((byte_delta * 8) // time_delta_sec)
                    #gbps = bps / 1e9

                    results.append({
                        "router_id": router_id,
                        "endpoint": endpoint,
                        "color": color,
                        "rate_bps": bps,
                        #"avg_gbps": round(gbps, 3),
                        "samples": len(rows),
                        "window_seconds": round(time_delta_sec, 1),
                    })

                conn.close()
            except Exception as e:
                self.logger.error(f'Sampling-server: Unable to read counters from DB: {e}')
                continue

            if len(results) > 0:
                for policy in results:
                    policy_key = f'[{policy["router_id"]}][{policy["endpoint"]}][{policy["color"]}]'
                    try:
                        if policy_key not in self.sampled_policies.keys():
                            self.logger.info(f'Sampling-server: Adding new policy {policy_key}, sampled rate {policy["rate_bps"]} bps')
                            self.sampled_policies[policy_key] = policy
                            self.sampled_policies[policy_key]["last_updated"] = int(time())
                            self.sampled_policies[policy_key]["stale"] = False
                            # send policy to BGP
                            self.sampling_to_bgp_queue.put(("update_policy", self.sampled_policies[policy_key]))
                        else:
                            if self.exceeds_adjust_threshold(self.sampled_policies[policy_key]["rate_bps"], policy["rate_bps"], self.sampling_options["adjust_threshold"]):
                                self.logger.info(f'Sampling-server: Policy {policy_key}, updating sampled rate {policy["rate_bps"]}')
                                self.sampled_policies[policy_key] = policy
                                self.sampled_policies[policy_key]["last_updated"] = int(time())
                                self.sampled_policies[policy_key]["stale"] = False
                                # send policy to BGP
                                self.sampling_to_bgp_queue.put(("update_policy", self.sampled_policies[policy_key]))
                            else:
                                self.logger.info(f'Sampling-server: Policy {policy_key}, sampled rate {policy["rate_bps"]} is less than adjust threshold, ignoring')
                                self.sampled_policies[policy_key]["last_updated"] = int(time())
                                self.sampled_policies[policy_key]["stale"] = False
                    except Exception as e:
                        self.logger.error(f'Sampling-server: Unable to update policy {policy_key}, exception {e}')


    def cleanup_old_policies(self):
        last_cleanup_time = int(time())
        while True:
            sleep(2)
            self.cleanup_old_policies_keepalive = int(time())
            if int(time()) - CLEANUP_TIMER < last_cleanup_time: continue
            self.logger.debug(f'Sampling-server: Cleaning up old policies')
            last_cleanup_time = int(time())
            delete_policies = []
            for policy_key, policy_value in self.sampled_policies.items():
                if policy_value["stale"]:
                    if int(time()) - policy_value["last_updated"] > self.actual_adjust_interval * 5:
                        delete_policies.append(policy_key)
                        # send policy to BGP
                        self.sampling_to_bgp_queue.put(("delete_policy", policy_value))
                else:
                    if int(time()) - policy_value["last_updated"] > self.actual_adjust_interval * 3:
                        self.logger.debug(f'Sampling-server: Marking policy {policy_key} as stale')
                        policy_value["stale"] = True
            for policy_name in delete_policies:
                if policy_name in self.sampled_policies.keys():
                    self.logger.debug(f'Sampling-server: Deleting stale policy {policy_key}')
                    del self.sampled_policies[policy_name]


    def get_sampling_to_bgp_query(self):
        if not self.sampling_to_bgp_queue.qsize(): return
        return self.sampling_to_bgp_queue.get()
    

    def start_samplers(self, client_ip=None):
        if not self.running: return
        if not client_ip:
            for current_client_ip, sampler in self.samplers.items():
                if sampler.running: continue
                self.logger.info(f'Sampling-server: Starting sampler {current_client_ip}')
                self.running_samplers[current_client_ip] = self.pool.spawn(sampler.run)
            return
        if client_ip not in self.samplers.keys(): return
        if self.samplers[client_ip].running: return
        self.logger.info(f'Sampling-server: Starting sampler {client_ip}')
        self.running_samplers[client_ip] = self.pool.spawn(sampler.run)
 

    def stop_samplers(self, client_ip=None):
        if not self.running: return
        if not client_ip:
            for current_client_ip, sampler in self.samplers.items():
                self.logger.info(f'Sampling-server: Stopping sampler {current_client_ip}')
                sampler.running = False
            for running_sampler in self.running_samplers.values():
                running_sampler.kill()
            self.running_samplers = {}
            return
        if client_ip not in self.samplers.keys(): return
        self.logger.info(f'Sampling-server: Stopping sampler {client_ip}')
        if client_ip not in self.running_samplers.keys(): return
        self.running_samplers[client_ip].kill()
        del self.running_samplers[client_ip]


    def show_command(self, query, command=None):
        self.logger.debug(f'Sampling-server: Received show command query {query}, arguments {command}')
        return self.responder.get_response(query, command)


    CLEAR_RESPONDERS = {
    }


    def clear_command(self, query, command=None):
        self.logger.debug(f'Sampling-server: Received clear command query {query}, arguments {command}')
        if query not in self.CLEAR_RESPONDERS.keys(): return
        return self.CLEAR_RESPONDERS[query](self, command)
    

    def debug_sampling_server(self, command=None, undebug=False):
        if undebug:
            self.logger.warning(f'Sampling-server: Disabling debug for Sampling server')
            self.logger.setLevel(logging.INFO)
            return {'warnings': ['Disabled debugging for Sampling server']}
        self.logger.warning(f'Sampling-server: Enabling debug for Sampling server')
        self.logger.setLevel(logging.DEBUG)
        return {'warnings': ['Enabled debugging for Sampling server']}


    def debug_sampling_clients(self, client_ip=None, undebug=False):
        if not client_ip: return
        if undebug:
            if client_ip == "*":
                self.logger.warning(f'Sampling-server: Disabling debug for all clients')
                for sampler in self.samplers.values():
                    if not sampler.logger: continue
                    sampler.logger.setLevel(logging.INFO)
                return {'warnings': ['Disabled debugging for all sampling clients']}
            if client_ip not in self.samplers.keys():
                self.logger.warning(f'Sampling-server: Unable to disable debug for client {client_ip} - client not configured')
                result = '{"warnings": ["Client %s is not configured"]}' % client_ip
                return json.loads(result)
            self.logger.warning(f'Sampling-server: Disabling debug for client {client_ip}')
            self.samplers[client_ip].logger.setLevel(logging.INFO)
            result = '{"warnings": ["Disabled debugging for sampling client %s"]}' % client_ip
            return json.loads(result)            
        if client_ip == "*":
            self.logger.warning(f'Sampling-server: Enabling debug for all clients')
            for sampler in self.samplers.values():
                if not sampler.logger: continue
                sampler.logger.setLevel(logging.DEBUG)
            return {'warnings': ['Enabled debugging for all sampling clients']}
        if client_ip not in self.samplers.keys():
            self.logger.warning(f'Sampling-server: Unable to enable debug for client {client_ip} - client not configured')
            result = '{"warnings": ["Client %s is not configured"]}' % client_ip
            return json.loads(result)
        self.logger.warning(f'Sampling-server: Enabling debug for client {client_ip}')
        self.samplers[client_ip].logger.setLevel(logging.DEBUG)
        result = '{"warnings": ["Enabled debugging for sampling client %s"]}' % client_ip
        return json.loads(result)
    

    DEBUG_RESPONDERS = {
        "sampling_server": debug_sampling_server,
        "sampling_clients": debug_sampling_clients
    }


    def debug_command(self, query, command=None, undebug=False):
        self.logger.debug(f'Sampling-server: Received debug command query {query}, arguments {command}')
        if query not in self.DEBUG_RESPONDERS.keys(): return
        return self.DEBUG_RESPONDERS[query](self, command, undebug=undebug)


    def update_logging_config(self, new_logging_config):
        self.logger.debug(f'Sampling-server: Updating logging config')
        logging.config.dictConfig(config=new_logging_config)
        formatter = HostnameFormatter(new_logging_config['formatters']['simple']['format'])
        for handler in logging.getLogger().handlers:
            handler.setFormatter(formatter)


    def return_keepalives(self):
        all_keepalives = {}
        all_keepalives["config_update_keepalive"] = self.config_update_keepalive
        all_keepalives["gnmi_streaming_keepalive"] = self.gnmi_streaming_keepalive
        all_keepalives["calculate_bandwidth_keepalive"] = self.calculate_bandwidth_keepalive
        all_keepalives["cleanup_old_policies_keepalive"] = self.cleanup_old_policies_keepalive
        return all_keepalives


    def run(self):
        self.running = True
        self.last_adjust_time = int(time())
        self.logger.info(f'Sampling-server: Sampling server started')
        self.process_all_clients()
        for client_ip, client_settings in self.processed_clients.items():
            sampler = GnmiSampler(client_ip, client_settings, self.gnmi_streaming_queue, self.sampling_options["sampling_interval"])
            self.samplers[client_ip] = sampler

        if self.running:
            self.start_samplers()

        self.pool.spawn(self.update_config) 
        self.pool.spawn(self.handle_streaming_updates)
        self.pool.spawn(self.calculate_average_bandwidth)
        self.pool.spawn(self.cleanup_old_policies)
        self.pool.waitall()
  

