#!/usr/bin/env python3

from pprint import pprint
from eventlet import GreenPool, listen, connect, greenthread, sleep, semaphore
from eventlet.queue import Queue
import socket
import struct
import json
from pyroute2 import IPRoute
from time import time
import logging
import logging.config
import ipaddress

class HostnameFormatter(logging.Formatter):
    def format(self, record):
        record.hostname = socket.gethostname()
        return super().format(record)

from .bgp_defaults import *
from .bgp_fsm import BgpFsm
from .bgp_session import BgpSession, BgpSessionCounters
from .bgp_message import *
from .bgp_rib import *
from .bgp_route import *
from .show_bgp_responder import ShowBgpResponder


class BgpNeighbor:
    def __init__(self, remote_ip, remote_as=None, keepalive_timer=BGP_KEEPALIVE_TIMER, hold_timer=BGP_HOLD_TIMER, address_families=[], passive=True, ebgp_multihop=None, shutdown=False, description=None):
        self.ipv6 = False
        if ":" in remote_ip:
            self.ipv6 = True
        self.remote_ip = remote_ip
        self.asn32_support = True
        self.remote_asn32 = False
        self.remote_as = remote_as
        if self.remote_as:
            if self.remote_as > 65535:
                self.remote_asn32 = True
        self.keepalive_timer = keepalive_timer
        self.hold_timer = hold_timer
        self.address_families = ["link-state"]
        self.passive = True
        self.ebgp_multihop = ebgp_multihop
        self.shutdown = shutdown
        self.description = description
        self.link_type = "external"
        self.remote_router_id = None
        self.local_ip = None
        self.local_as = None
        self.local_asn32 = False
        self.local_router_id = None
        self.bgp_server = None
        self.ls_adj_rib_in = None
        self.RIB_INS = {}
        self.ls_adj_rib_out = None
        self.RIB_OUTS = {}
        self.fsm = None
        self.counters = None
        self.session = None
        self.logger = logging.getLogger(f'bgp_{self.remote_ip}')



    def resolve_local_ip(self):
        self.logger.debug(f'Bgp neighbor {self.remote_ip}: Attempting to resolve local IP')
        try:
            with IPRoute() as ipr:
                local_ip = ipr.route('get', dst=self.remote_ip)[0]["attrs"][3][1]
                if local_ip:
                    if local_ip.startswith("fe80"): return None
                return local_ip
        except:
            self.logger.debug(f'Bgp neighbor {self.remote_ip}: Unable to resolve local IP')
            return None
        
    def update_local_ip(self, local_ip=None):
        if local_ip:
            self.local_ip = local_ip
        else:
            self.local_ip = self.resolve_local_ip()
            

    def set_remote_as(self, remote_as):
        self.remote_as = remote_as
        self.logger.debug(f'Bgp neighbor {self.remote_ip}: Set remote AS to {self.remote_as}')
        self.remote_asn32 = False
        self.link_type = "external"
        if self.remote_as:
            if self.remote_as > 65535:
                self.remote_asn32 = True
                self.logger.debug(f'Bgp neighbor {self.remote_ip}: Remote AS is a 4-byte ASN')
            if self.local_as == self.remote_as:
                self.link_type = "internal"
                self.logger.debug(f'Bgp neighbor {self.remote_ip}: Set link type to Internal')
                if self.session:
                    self.session.ttl = 255
                    self.logger.debug(f'Bgp neighbor {self.remote_ip}: Set session TTL to 255')
            else:
                self.logger.debug(f'Bgp neighbor {self.remote_ip}: Set link type to External')
                if self.session:
                    if self.ebgp_multihop:
                        self.session.ttl = self.ebgp_multihop
                        self.logger.debug(f'Bgp neighbor {self.remote_ip}: Set session TTL to {self.session.ttl}')
                    else:
                        self.session.ttl = 1
                        self.logger.debug(f'Bgp neighbor {self.remote_ip}: Set session TTL to 1')


    def set_locals(self, local_ip, local_as, local_router_id):
        self.local_ip = local_ip
        self.logger.debug(f'Bgp neighbor {self.remote_ip}: Set local IP to {self.local_ip}')
        self.local_as = local_as
        self.logger.debug(f'Bgp neighbor {self.remote_ip}: Set local AS to {self.local_as}')
        if self.local_as:
            if self.local_as > 65535:
                self.local_asn32 = True
                self.logger.debug(f'Bgp neighbor {self.remote_ip}: Local AS is a 4-byte ASN')
        self.local_router_id = local_router_id
        self.logger.debug(f'Bgp neighbor {self.remote_ip}: Set local Router-ID to {self.local_router_id}')
        if self.local_as == self.remote_as:
            self.logger.debug(f'Bgp neighbor {self.remote_ip}: Set link type to Internal')
            self.link_type = "internal"

    def set_capabilities(self):
        self.capabilities = copy.deepcopy(BgpCapability.DEFAULT_CAPABILITIES)
        self.capabilities.append({'code': BgpCapability.ASN32, 'len': 4, 'value': self.local_as})
        if self.address_families:
            for af in self.address_families:
                if af in BgpCapability.ADDRESS_FAMILIES:
                    self.capabilities.append(BgpCapability.ADDRESS_FAMILIES[af])
                    self.logger.debug(f'Bgp neighbor {self.remote_ip}: Added capability {af}')

    
    def set_dynamics(self, bgp_server):
        self.bgp_server = bgp_server
        LOC_RIBS = bgp_server.LOC_RIBS
        self.ls_adj_rib_in = BgpAdjRibIn(self, BgpCapability.BgpAfi.LS, BgpCapability.BgpSafi.LS, LOC_RIBS["link-state"], self.logger)
        self.RIB_INS = {
            'link-state': self.ls_adj_rib_in}
        self.ls_adj_rib_out = BgpAdjRibOut(self, BgpCapability.BgpAfi.LS, BgpCapability.BgpSafi.LS, LOC_RIBS["link-state"], self.logger)
        self.RIB_OUTS = {
            'link-state': self.ls_adj_rib_out}
        self.fsm = BgpFsm(self)
        self.counters = BgpSessionCounters(self)
        self.session = BgpSession(self)
        self.logger.debug(f'Bgp neighbor {self.remote_ip}: Set dynamics')
        if self.shutdown is True:
            self.session.admin_down = True
            self.logger.debug(f'Bgp neighbor {self.remote_ip}: Set session as Admin down')


    def return_received_nlri_count(self, rib_name=None):
        if rib_name:
            self.logger.debug(f'Bgp neighbor {self.remote_ip}: Returning received NLRI count for rib {rib_name}')
            rib_in = self.RIB_INS.get(rib_name, None)
            if not rib_in: return 0
            return rib_in.return_received_nlri_count()

        self.logger.debug(f'Bgp neighbor {self.remote_ip}: Returning received NLRI count for all ribs')
        nlri_count = 0
        for rib_in in self.RIB_INS.values():
            if not rib_in: continue
            nlri_count += rib_in.return_received_nlri_count()
        return nlri_count


    def return_sent_nlri_count(self, rib_name=None):
        if rib_name:
            self.logger.debug(f'Bgp neighbor {self.remote_ip}: Returning sent NLRI count for rib {rib_name}')
            rib_out = self.RIB_OUTS.get(rib_name, None)
            if not rib_out: return 0
            return rib_out.return_sent_nlri_count()

        self.logger.debug(f'Bgp neighbor {self.remote_ip}: Returning sent NLRI count for all ribs')
        nlri_count = 0
        for rib_out in self.RIB_OUTS.values():
            if not rib_out: continue
            nlri_count += rib_out.return_sent_nlri_count()
        return nlri_count


class BgpServer:
    def __init__(self, bgp_config):
        self.ipv4_address = ("0.0.0.0", BGP_TCP_PORT)
        self.ipv6_address = ("::", BGP_TCP_PORT)
        self.asn = bgp_config["asn"]
        self.router_id = bgp_config["router_id"]
        self.configured_neighbors = bgp_config["neighbors"]
        self.responder = ShowBgpResponder(self)
        self.neighbors = {}
        self.running_sessions = {}
        self.running_ribs = {}
        self.running = False
        self.config_updates = Queue()
        self.signal_queue = Queue()
        self.pool = GreenPool()
        self.logger = logging.getLogger("bgp_server")
        self.ls_loc_rib = BgpLocRib(BgpCapability.BgpAfi.LS, BgpCapability.BgpSafi.LS, self.logger)
        self.LOC_RIBS = {
            'link-state': self.ls_loc_rib}
        self.policies = {}
        self.config_update_keepalive = 0
        self.signal_receiver_keepalive = 0
        


    def handle_asn_change(self, change_type, change_path, change_values, running_config):
        # either BGP config is deleted, or a new BGP process is configured
        self.logger.debug(f'Bgp: Changing ASN from {self.asn} to {change_values["new_value"]}')
        if change_type != "type_changes": return
        if change_values["new_value"] is None:
            self.stop_neighbors(deconfigured=True)
            self.logger.debug(f'Bgp: ASN deconfigured, stopped all neighbors')
            self.running = False
            self.logger.info(f'Bgp: BGP server stopped')
            self.asn = None
            self.router_id = None
            self.configured_neighbors = []
            self.neighbors = {}
            self.running_sessions = {}
            self.ls_loc_rib = BgpLocRib(BgpCapability.BgpAfi.LS, BgpCapability.BgpSafi.LS, self.logger)
            self.LOC_RIBS = {
                'link-state': self.ls_loc_rib}
            for running_rib in self.running_ribs.values():
                running_rib.kill()
            self.logger.debug(f'Bgp: Stopped all BGP Ribs')
            self.running_ribs = {}
        else:
            self.asn = change_values["new_value"]
            self.logger.debug(f'Bgp: Set ASN to {self.asn}')
            if self.router_id:
                self.logger.error(f'Bgp: Somehow router-id {self.router_id} is set while ASN was not configured, this should never happen')


    def handle_router_id_change(self, change_type, change_path, change_values, running_config):       
        # RID change - update locals for all neighbors and reset sessions
        self.logger.debug(f'Bgp: Changing Router-ID from {self.router_id} to {change_values["new_value"]}')
        if change_type == "values_changed":
            self.router_id = change_values["new_value"]
            for neighbor in self.neighbors.values():
                local_ip = neighbor.resolve_local_ip()
                neighbor.set_locals(local_ip, self.asn, self.router_id)
            self.logger.debug(f'Bgp: Router-ID changed, resetting all BGP neighbors')
            self.reset_neighbors()
            return
        if change_type != "type_changes": return
        # RID unset
        if change_values["new_value"] is None:
            if self.running:
                self.logger.debug(f'Bgp: Router-ID deconfigured, stopped all neighbors')
                self.stop_neighbors()
                self.router_id = None
                self.running = False
                self.logger.info(f'Bgp: BGP server stopped')
                self.running_sessions = {}
                for running_rib in self.running_ribs.values():
                    running_rib.kill()
                self.logger.debug(f'Bgp: Stopped all BGP Ribs')
                self.running_ribs = {}
            for neighbor in self.neighbors.values():
                local_ip = neighbor.resolve_local_ip()
                neighbor.set_locals(local_ip, self.asn, self.router_id)
        # new RID set
        else:
            self.router_id = change_values["new_value"]
            self.logger.debug(f'Bgp: Set Router-ID to {self.router_id}')
            for neighbor in self.neighbors.values():
                local_ip = neighbor.resolve_local_ip()
                neighbor.set_locals(local_ip, self.asn, self.router_id)
            self.running = True
            self.logger.info(f'Bgp: BGP server started')
            for loc_rib_name, loc_rib in self.LOC_RIBS.items():
                self.running_ribs[loc_rib_name] = self.pool.spawn(loc_rib.process_route_changes)
            self.start_neighbors()
            


    def handle_neighbor_change(self, change_type, change_path, change_values, running_config):
        if change_type == "iterable_item_added":
            self.logger.debug(f'Bgp: Adding new neighbor {change_values["remote_ip"]}')
            if change_values["remote_ip"] in self.neighbors.keys():
                self.logger.debug(f'Bgp: Stopping neighbor {change_values["remote_ip"]}')
                self.stop_neighbors(change_values["remote_ip"])
            neighbor_found = False
            for configured_neighbor in self.configured_neighbors:
                if configured_neighbor["remote_ip"] == change_values["remote_ip"]:
                    neighbor_found = True
                    neighbor = BgpNeighbor(**configured_neighbor)
                    break
            if not neighbor_found:
                neighbor = BgpNeighbor(change_values["remote_ip"])
            self.neighbors[neighbor.remote_ip] = neighbor
            local_ip = neighbor.resolve_local_ip()
            neighbor.set_locals(local_ip, self.asn, self.router_id)
            neighbor.set_capabilities()
            neighbor.set_dynamics(self)
            self.neighbors = dict(sorted(self.neighbors.items(), key=lambda item: (ipaddress.ip_address(item[0]).version, ipaddress.ip_address(item[0]))))
            self.logger.debug(f'Bgp: Starting neighbor {change_values["remote_ip"]}')
            self.start_neighbors(change_values["remote_ip"])
        elif change_type == "values_changed":
            self.logger.debug(f'Bgp: Changing neighbor {change_values["new_value"]["remote_ip"]}')
            if change_values["new_value"]["remote_ip"] in self.neighbors.keys():
                self.logger.debug(f'Bgp: Stopping neighbor {change_values["new_value"]["remote_ip"]}')
                self.stop_neighbors(change_values["new_value"]["remote_ip"])
            neighbor_found = False
            for configured_neighbor in self.configured_neighbors:
                if configured_neighbor["remote_ip"] == change_values["new_value"]["remote_ip"]:
                    neighbor_found = True
                    neighbor = BgpNeighbor(**configured_neighbor)
                    break
            if not neighbor_found:
                neighbor = BgpNeighbor(change_values["new_value"]["remote_ip"])
            self.neighbors[neighbor.remote_ip] = neighbor
            local_ip = neighbor.resolve_local_ip()
            neighbor.set_locals(local_ip, self.asn, self.router_id)
            neighbor.set_capabilities()
            neighbor.set_dynamics(self)
            self.neighbors = dict(sorted(self.neighbors.items(), key=lambda item: (ipaddress.ip_address(item[0]).version, ipaddress.ip_address(item[0]))))
            self.logger.debug(f'Bgp: Starting neighbor {change_values["new_value"]["remote_ip"]}')
            self.start_neighbors(change_values["new_value"]["remote_ip"])
        elif change_type == "iterable_item_removed":
            self.logger.debug(f'Bgp: Deleting neighbor {change_values["remote_ip"]}')
            if self.running and change_values["remote_ip"] in self.neighbors.keys():
                self.stop_neighbors(change_values["remote_ip"], deconfigured=True)
            del self.neighbors[change_values["remote_ip"]]


    def handle_description_change(self, change_type, change_path, change_values, running_config):
        nbr_index = int(change_path[0])
        neighbor_ip = self.configured_neighbors[nbr_index]["remote_ip"]
        self.logger.debug(f'Bgp: Changing description for neighbor {neighbor_ip}')
        if change_type == "dictionary_item_added":
            if neighbor_ip in self.neighbors.keys():
                self.neighbors[neighbor_ip].description = self.configured_neighbors[nbr_index]["description"]
        elif change_type == "dictionary_item_removed":
            if neighbor_ip in self.neighbors.keys():
                self.neighbors[neighbor_ip].description = None
        elif change_type == "values_changed":
            if neighbor_ip in self.neighbors.keys():
                self.neighbors[neighbor_ip].description = change_values["new_value"]


    def handle_remote_as_change(self, change_type, change_path, change_values, running_config):
        nbr_index = int(change_path[0])
        neighbor_ip = self.configured_neighbors[nbr_index]["remote_ip"]        
        if change_type == "dictionary_item_added":
            if neighbor_ip in self.neighbors.keys():
                self.logger.debug(f'Bgp: Setting remote ASN for neighbor {neighbor_ip} to {self.configured_neighbors[nbr_index]["remote_as"]}')
                self.neighbors[neighbor_ip].set_remote_as(self.configured_neighbors[nbr_index]["remote_as"])
                self.start_neighbors(neighbor_ip)
        elif change_type == "dictionary_item_removed":
            if neighbor_ip in self.neighbors.keys():
                self.logger.debug(f'Bgp: Unsetting remote ASN for neighbor {neighbor_ip}')
                self.stop_neighbors(neighbor_ip)
                self.neighbors[neighbor_ip].set_remote_as(None)
        elif change_type == "values_changed":
            if neighbor_ip in self.neighbors.keys():
                self.logger.debug(f'Bgp: Changing remote ASN for neighbor {neighbor_ip} to {change_values["new_value"]}')
                self.neighbors[neighbor_ip].set_remote_as(change_values["new_value"])
                self.logger.debug(f'Bgp: Resetting neighbor {neighbor_ip}')
                self.reset_neighbors(neighbor_ip)


    def handle_keepalive_timer_change(self, change_type, change_path, change_values, running_config):
        nbr_index = int(change_path[0])
        neighbor_ip = self.configured_neighbors[nbr_index]["remote_ip"]
        if change_type == "dictionary_item_added":
            self.logger.debug(f'Bgp: Setting Keepalive timer for neighbor {neighbor_ip} to {self.configured_neighbors[nbr_index]["keepalive_timer"]}')
            keepalive_timer = self.configured_neighbors[nbr_index]["keepalive_timer"]
        elif change_type == "dictionary_item_removed":
            self.logger.debug(f'Bgp: Setting Keepalive timer for neighbor {neighbor_ip} to {BGP_KEEPALIVE_TIMER}')
            keepalive_timer = BGP_KEEPALIVE_TIMER
        elif change_type == "values_changed":
            self.logger.debug(f'Bgp: Setting Keepalive timer for neighbor {neighbor_ip} to {change_values["new_value"]}')
            keepalive_timer = change_values["new_value"]
        if neighbor_ip in self.neighbors.keys():
            self.neighbors[neighbor_ip].keepalive_timer = keepalive_timer
            self.neighbors[neighbor_ip].fsm.set_keepalive_timer(keepalive_timer)
            self.logger.debug(f'Bgp: Resetting neighbor {neighbor_ip}')
            self.reset_neighbors(neighbor_ip)


    def handle_hold_timer_change(self, change_type, change_path, change_values, running_config):
        nbr_index = int(change_path[0])
        neighbor_ip = self.configured_neighbors[nbr_index]["remote_ip"]
        if change_type == "dictionary_item_added":
            self.logger.debug(f'Bgp: Setting Hold timer for neighbor {neighbor_ip} to {self.configured_neighbors[nbr_index]["hold_timer"]}')
            hold_timer = self.configured_neighbors[nbr_index]["hold_timer"]
        elif change_type == "dictionary_item_removed":
            self.logger.debug(f'Bgp: Setting Hold timer for neighbor {neighbor_ip} to {BGP_HOLD_TIMER}')
            hold_timer = BGP_HOLD_TIMER
        elif change_type == "values_changed":
            self.logger.debug(f'Bgp: Setting Hold timer for neighbor {neighbor_ip} to {change_values["new_value"]}')
            hold_timer = change_values["new_value"]
        if neighbor_ip in self.neighbors.keys():
            self.neighbors[neighbor_ip].hold_timer = hold_timer
            self.neighbors[neighbor_ip].fsm.set_hold_timer(hold_timer)
            self.logger.debug(f'Bgp: Resetting neighbor {neighbor_ip}')
            self.reset_neighbors(neighbor_ip)


    def handle_ebgp_multihop_change(self, change_type, change_path, change_values, running_config):
        nbr_index = int(change_path[0])
        neighbor_ip = self.configured_neighbors[nbr_index]["remote_ip"]
        if change_type == "dictionary_item_added":
            if neighbor_ip in self.neighbors.keys():
                self.logger.debug(f'Bgp: Setting Ebgp-multihop for neighbor {neighbor_ip} to {self.configured_neighbors[nbr_index]["ebgp_multihop"]}')
                self.neighbors[neighbor_ip].ebgp_multihop = self.configured_neighbors[nbr_index]["ebgp_multihop"]
        elif change_type == "dictionary_item_removed":
            if neighbor_ip in self.neighbors.keys():
                self.logger.debug(f'Bgp: Removing Ebgp-multihop for neighbor {neighbor_ip}')
                self.neighbors[neighbor_ip].ebgp_multihop = None
        elif change_type == "values_changed":
            if neighbor_ip in self.neighbors.keys():
                self.logger.debug(f'Bgp: Setting Ebgp-multihop for neighbor {neighbor_ip} to {change_values["new_value"]}')
                self.neighbors[neighbor_ip].ebgp_multihop = change_values["new_value"]
        if neighbor_ip in self.neighbors.keys():
            if self.neighbors[neighbor_ip].session and self.neighbors[neighbor_ip].link_type == "external":
                if self.neighbors[neighbor_ip].ebgp_multihop:
                    self.neighbors[neighbor_ip].session.ttl = self.neighbors[neighbor_ip].ebgp_multihop
                else:
                    self.neighbors[neighbor_ip].session.ttl = 1
                self.logger.debug(f'Bgp: Resetting neighbor {neighbor_ip}')
                self.reset_neighbors(neighbor_ip)


    def handle_shutdown_change(self, change_type, change_path, change_values, running_config):
        nbr_index = int(change_path[0])
        neighbor_ip = self.configured_neighbors[nbr_index]["remote_ip"]
        if change_type == "dictionary_item_added":
            self.logger.debug(f'Bgp: Shutting down neighbor {neighbor_ip}')
            if neighbor_ip in self.neighbors.keys():
                self.stop_neighbors(neighbor_ip)
                self.neighbors[neighbor_ip].shutdown = True
        elif change_type == "dictionary_item_removed":
            self.logger.debug(f'Bgp: Unshutting neighbor {neighbor_ip}')
            if neighbor_ip in self.neighbors.keys():
                self.neighbors[neighbor_ip].shutdown = False
                self.neighbors[neighbor_ip].fsm.shutdown_requested = False
                self.start_neighbors(neighbor_ip)


    BGP_NEIGHBOR_CHANGES = {
        "neighbor": handle_neighbor_change,
        "description": handle_description_change,
        "remote_as": handle_remote_as_change,
        "keepalive_timer": handle_keepalive_timer_change,
        "hold_timer": handle_hold_timer_change,
        "ebgp_multihop": handle_ebgp_multihop_change,
        "shutdown": handle_shutdown_change
    }
        

    def handle_neighbors(self, change_type, change_path, change_values, running_config):
        if not self.asn: return
        self.logger.debug(f'Bgp: Updating neighbors config')
        self.configured_neighbors = running_config["bgp"]["neighbors"]
        if len(change_path) == 1:
            change_keyword = "neighbor"
        else:
            change_keyword = change_path[1]
        self.logger.debug(f'Bgp: Changing neighbors config, keyword {change_keyword}')
        if change_keyword in self.BGP_NEIGHBOR_CHANGES.keys():
            change_handler = self.BGP_NEIGHBOR_CHANGES[change_keyword]
            change_handler(self, change_type, change_path, change_values, running_config)

    BGP_CONFIG_CHANGES = {
        "asn": handle_asn_change,
        "router_id": handle_router_id_change,
        "neighbors": handle_neighbors
    }


    def add_config_changes(self, change_type, change_server, changes_list, running_config=None):
        for change_item in changes_list:
            self.logger.debug(f'Bgp: Queuing config change {change_type}, {change_item[0]}, {change_item[1]}')
            self.config_updates.put((change_type, change_server, change_item[0], change_item[1], running_config))


    def update_config(self):
        while True:
            sleep(2)
            self.config_update_keepalive = int(time())
            if not self.config_updates.qsize(): continue
            init_time = round(time()*1000)
            while self.config_updates.qsize():
                self.logger.debug(f'Bgp: Fetching config updates')
                if round(time()*1000) - init_time > 200: break
                change_type, change_server, change_path_processed, change_values, running_config = self.config_updates.get()
                if change_server == "bgp":
                    if change_path_processed[0] in self.BGP_CONFIG_CHANGES.keys():
                        change_handler = self.BGP_CONFIG_CHANGES[change_path_processed[0]]
                        try:
                            change_handler(self, change_type, change_path_processed[1:], change_values, running_config)
                        except:
                            self.logger.exception(f'Bgp: Unable to process config change for {change_server}, {change_type}, {change_path_processed}, {change_values}')


    def add_signals(self, signal):
        self.logger.debug(f'Bgp: Adding signals to queue')
        self.signal_queue.put(signal)


    def receive_incoming_signal(self):
        while True:
            sleep(0.2)
            if int(time()) > self.signal_receiver_keepalive:
                self.signal_receiver_keepalive = int(time())
            if not self.signal_queue.qsize(): continue
            init_time = round(time()*1000)
            while self.signal_queue.qsize():
                self.logger.debug(f'Bgp: Receiving signals')
                if round(time()*1000) - init_time > 200: break
                signal, args = self.signal_queue.get()
                if signal == "pfx_limit":
                    self.stop_neighbors(args, pfx_limit=True)


    def start_neighbors(self, neighbor_ip=None):
        if not self.running: return
        # start specific neighbor session or all sessions if it's not admin down and not already running
        if not neighbor_ip:
            for neighbor in self.neighbors.values():
                if neighbor.shutdown: continue
                if not neighbor.remote_as: continue
                if not neighbor.session: continue
                if neighbor.session.running: continue
                self.logger.info(f'Bgp: Starting BGP session for neighbor {neighbor.remote_ip}')
                self.running_sessions[neighbor.remote_ip] = self.pool.spawn(neighbor.session.run)
            return
        if neighbor_ip not in self.neighbors.keys(): return
        if self.neighbors[neighbor_ip].shutdown: return
        if not self.neighbors[neighbor_ip].remote_as: return
        if not self.neighbors[neighbor_ip].session: return
        if self.neighbors[neighbor_ip].session.running: return
        self.logger.info(f'Bgp: Starting BGP session for neighbor {neighbor_ip}')
        self.running_sessions[neighbor_ip] = self.pool.spawn(self.neighbors[neighbor_ip].session.run)
 

    def stop_neighbors(self, neighbor_ip=None, deconfigured=False, pfx_limit=False):
        if not self.running: return
        if not neighbor_ip:
            for neighbor in self.neighbors.values():
                self.logger.info(f'Bgp: Stopping BGP session for neighbor {neighbor.remote_ip}')
                neighbor.session.stop_session(deconfigured, pfx_limit)
            for running_session in self.running_sessions.values():
                running_session.kill()
            self.running_sessions = {}
            return
        if neighbor_ip not in self.neighbors.keys(): return
        if self.neighbors[neighbor_ip].shutdown: return
        if not self.neighbors[neighbor_ip].session: return
        self.logger.info(f'Bgp: Stopping BGP session for neighbor {neighbor_ip}')
        self.neighbors[neighbor_ip].session.stop_session(deconfigured, pfx_limit)
        if neighbor_ip not in self.running_sessions.keys(): return 
        self.running_sessions[neighbor_ip].kill()
        del self.running_sessions[neighbor_ip]


    def reset_neighbors(self, neighbor_ip=None):
        if not self.running: return
        # reset specific neighbor session or all sessions unless the session is stopped
        if not neighbor_ip:
            for neighbor in self.neighbors.values():
                if neighbor.shutdown: continue
                if not neighbor.session: continue
                if not neighbor.session.running: continue
                self.logger.info(f'Bgp: Resetting BGP session for neighbor {neighbor.remote_ip}')
                neighbor.session.reset_session()
            return
        if neighbor_ip not in self.neighbors.keys(): return
        if self.neighbors[neighbor_ip].shutdown: return
        if not self.neighbors[neighbor_ip].session: return
        if not self.neighbors[neighbor_ip].session.running: return
        self.logger.info(f'Bgp: Resetting BGP session for neighbor {neighbor_ip}')
        self.neighbors[neighbor_ip].session.reset_session()

    def show_command(self, query, command=None):
        self.logger.debug(f'Bgp: Received show command query {query}, arguments {command}')
        return self.responder.get_response(query, command)

    def clear_bgp_neighbors(self, neighbor_ip=None):
        if not neighbor_ip: return
        if self.ls_loc_rib.update_route_queue.qsize() > 100000:
            return {'warnings': ['Update queue for BGP-LS Loc-Rib is over 100k routes, clearing will make it worse. Please shutdown some neighbors. Check "show bgp internal" to see update queue size.']}
        if neighbor_ip == "*":
            self.logger.warning(f'Bgp: Clearing all BGP neighbors in and out (soft)')
            for neighbor in self.neighbors.values():
                if neighbor.fsm.state == "Established":
                    neighbor.session.send_route_refresh()
                    for af, rib_out in neighbor.RIB_OUTS.items():
                        if not rib_out: continue
                        if BgpCapability.ADDRESS_FAMILIES[af] not in neighbor.fsm.negotiated_capabilities: continue
                        rib_out.refresh_all_routes()
                        rib_out.advertise_routes()
            return {'warnings': ['Peerings for all neighbors were soft (in and out) reset']}
        if neighbor_ip not in self.neighbors.keys():
            self.logger.warning(f'Bgp: Unable to clear neighbor {neighbor_ip} in and out (soft) - neighbor not configured')
            result = '{"warnings": ["Neighbor %s is not configured"]}' % neighbor_ip
            return json.loads(result)
        if self.neighbors[neighbor_ip].fsm.state != "Established":
            self.logger.warning(f'Bgp: Unable to clear neighbor {neighbor_ip} in and out (soft) - neighbor not up')
            result =  '{"warnings": ["Neighbor %s is not up"]}' % neighbor_ip
            return json.loads(result)
        self.neighbors[neighbor_ip].session.send_route_refresh()
        self.logger.warning(f'Bgp: Sent route refresh to neighbor {neighbor_ip}')
        for af, rib_out in self.neighbors[neighbor_ip].RIB_OUTS.items():
            if not rib_out: continue
            if BgpCapability.ADDRESS_FAMILIES[af] not in self.neighbors[neighbor_ip].fsm.negotiated_capabilities: continue
            rib_out.refresh_all_routes()
            rib_out.advertise_routes()
        self.logger.warning(f'Bgp: Readvertised all routes to neighbor {neighbor_ip}')
        result = '{"warnings": ["Neighbor %s was soft (in and out) reset"]}' % neighbor_ip
        return json.loads(result) 

    def clear_bgp_neighbors_in(self, neighbor_ip=None):
        if not neighbor_ip: return
        if self.ls_loc_rib.update_route_queue.qsize() > 100000:
            return {'warnings': ['Update queue for BGP-LS Loc-Rib is over 100k routes, clearing will make it worse. Please shutdown some neighbors. Check "show bgp internal" to see update queue size.']}
        self.logger.warning(f'Bgp: Clearing all BGP neighbors in (soft)')
        if neighbor_ip == "*":
            for neighbor in self.neighbors.values():
                if neighbor.fsm.state == "Established":
                    neighbor.session.send_route_refresh()
            return {'warnings': ['Peerings for all neighbors were soft (in) reset']}
        if neighbor_ip not in self.neighbors.keys():
            self.logger.warning(f'Bgp: Unable to clear neighbor {neighbor_ip} in (soft) - neighbor not configured')
            result = '{"warnings": ["Neighbor %s is not configured"]}' % neighbor_ip
            return json.loads(result)
        if self.neighbors[neighbor_ip].fsm.state != "Established":
            self.logger.warning(f'Bgp: Unable to clear neighbor {neighbor_ip} in (soft) - neighbor not up')
            result =  '{"warnings": ["Neighbor %s is not up"]}' % neighbor_ip
            return json.loads(result)
        self.neighbors[neighbor_ip].session.send_route_refresh()
        self.logger.warning(f'Bgp: Sent route refresh to neighbor {neighbor_ip}')
        result = '{"warnings": ["Neighbor %s was soft (in) reset"]}' % neighbor_ip
        return json.loads(result)

    def clear_bgp_neighbors_out(self, neighbor_ip=None):
        if not neighbor_ip: return
        self.logger.warning(f'Bgp: Clearing all BGP neighbors out (soft)')
        if neighbor_ip == "*":
            for neighbor in self.neighbors.values():
                if neighbor.fsm.state == "Established":
                    for af, rib_out in neighbor.RIB_OUTS.items():
                        if not rib_out: continue
                        if BgpCapability.ADDRESS_FAMILIES[af] not in neighbor.fsm.negotiated_capabilities: continue
                        rib_out.refresh_all_routes()
                        rib_out.advertise_routes()
            return {'warnings': ['Peerings for all neighbors were soft (out) reset']}
        if neighbor_ip not in self.neighbors.keys():
            self.logger.warning(f'Bgp: Unable to clear neighbor {neighbor_ip} out (soft) - neighbor not configured')
            result = '{"warnings": ["Neighbor %s is not configured"]}' % neighbor_ip
            return json.loads(result)
        if self.neighbors[neighbor_ip].fsm.state != "Established":
            self.logger.warning(f'Bgp: Unable to clear neighbor {neighbor_ip} out (soft) - neighbor not up')
            result =  '{"warnings": ["Neighbor %s is not up"]}' % neighbor_ip
            return json.loads(result)
        for af, rib_out in self.neighbors[neighbor_ip].RIB_OUTS.items():
            if not rib_out: continue
            if BgpCapability.ADDRESS_FAMILIES[af] not in self.neighbors[neighbor_ip].fsm.negotiated_capabilities: continue
            rib_out.refresh_all_routes()
            rib_out.advertise_routes()
        self.logger.warning(f'Bgp: Readvertised all routes to neighbor {neighbor_ip}')
        result = '{"warnings": ["Neighbor %s was soft (out) reset"]}' % neighbor_ip
        return json.loads(result)            
                

    def clear_bgp_neighbors_hard(self, neighbor_ip=None):
        if not neighbor_ip: return
        self.logger.warning(f'Bgp: Clearing all BGP neighbors (hard)')
        if self.ls_loc_rib.update_route_queue.qsize() > 50000:
            return {'warnings': ['Update queue for BGP-LS Loc-Rib is over 50k routes, please use shutdown instead of hard clear. Check "show bgp internal" to see update queue size.']}
        if neighbor_ip == "*":
            #total_received_nlri_count = 0
            #for neighbor in self.neighbors.values():
            #    total_received_nlri_count += neighbor.return_received_nlri_count()
            #if total_received_nlri_count > 100000:
            #    return {'warnings': ['Command not supported on high scale, please clear each neighbor separately']}
            self.reset_neighbors()
            return {'warnings': ['Peerings for all neighbors were hard reset']}
        if neighbor_ip not in self.neighbors.keys():
            self.logger.warning(f'Bgp: Unable to clear neighbor {neighbor_ip} (hard) - neighbor not configured')
            result = '{"warnings": ["Neighbor %s is not configured"]}' % neighbor_ip
            return json.loads(result)
        if self.neighbors[neighbor_ip].shutdown:
            self.logger.warning(f'Bgp: Unable to clear neighbor {neighbor_ip} (hard) - neighbor not up')
            result =  '{"warnings": ["Neighbor %s is admin down"]}' % neighbor_ip
            return json.loads(result)
        self.reset_neighbors(neighbor_ip)
        self.logger.warning(f'Bgp: Cleared neighbor {neighbor_ip} (hard)')
        result = '{"warnings": ["Neighbor %s was hard reset"]}' % neighbor_ip
        return json.loads(result)
        

    CLEAR_RESPONDERS = {
        "bgp_neighbors": clear_bgp_neighbors,
        "bgp_neighbors_in": clear_bgp_neighbors_in,
        "bgp_neighbors_out": clear_bgp_neighbors_out,
        "bgp_neighbors_hard": clear_bgp_neighbors_hard
    }

    def clear_command(self, query, command=None):
        self.logger.debug(f'Bgp: Received clear command query {query}, arguments {command}')
        if query not in self.CLEAR_RESPONDERS.keys(): return
        return self.CLEAR_RESPONDERS[query](self, command)
    
    def debug_bgp_server(self, command=None, undebug=False):
        if undebug:
            self.logger.warning(f'Bgp: Disabling debug for BGP server')
            self.logger.setLevel(logging.INFO)
            return {'warnings': ['Disabled debugging for BGP server']}
        self.logger.warning(f'Bgp: Enabling debug for BGP server')
        self.logger.setLevel(logging.DEBUG)
        return {'warnings': ['Enabled debugging for BGP server']}
    
    def debug_bgp_neighbors(self, neighbor_ip=None, undebug=False):
        if not neighbor_ip: return
        if undebug:
            if neighbor_ip == "*":
                self.logger.warning(f'Bgp: Disabling debug for all BGP neighbors')
                for neighbor in self.neighbors.values():
                    if not neighbor.logger: continue
                    neighbor.logger.setLevel(logging.INFO)
                return {'warnings': ['Disabled debugging for all BGP neighbors']}
            if neighbor_ip not in self.neighbors.keys():
                self.logger.warning(f'Bgp: Unable to disable debug for BGP neighbor {neighbor_ip} - neighbor not configured')
                result = '{"warnings": ["Neighbor %s is not configured"]}' % neighbor_ip
                return json.loads(result)
            self.logger.warning(f'Bgp: Disabling debug for BGP neighbor {neighbor_ip}')
            self.neighbors[neighbor_ip].logger.setLevel(logging.INFO)
            result = '{"warnings": ["Disabled debugging for BGP neighbor %s"]}' % neighbor_ip
            return json.loads(result)            
        if neighbor_ip == "*":
            self.logger.warning(f'Bgp: Enabling debug for all BGP neighbors')
            for neighbor in self.neighbors.values():
                if not neighbor.logger: continue
                neighbor.logger.setLevel(logging.DEBUG)
            return {'warnings': ['Enabled debugging for all BGP neighbors']}
        if neighbor_ip not in self.neighbors.keys():
            self.logger.warning(f'Bgp: Unable to enable debug for BGP neighbor {neighbor_ip} - neighbor not configured')
            result = '{"warnings": ["Neighbor %s is not configured"]}' % neighbor_ip
            return json.loads(result)
        self.logger.warning(f'Bgp: Enabling debug for BGP neighbor {neighbor_ip}')
        self.neighbors[neighbor_ip].logger.setLevel(logging.DEBUG)
        result = '{"warnings": ["Enabled debugging for BGP neighbor %s"]}' % neighbor_ip
        return json.loads(result)      


    DEBUG_RESPONDERS = {
        "bgp_server": debug_bgp_server,
        "bgp_neighbors": debug_bgp_neighbors
    }


    def debug_command(self, query, command=None, undebug=False):
        self.logger.debug(f'Bgp: Received debug command query {query}, arguments {command}')
        if query not in self.DEBUG_RESPONDERS.keys(): return
        return self.DEBUG_RESPONDERS[query](self, command, undebug=undebug)


    @staticmethod
    def generate_sr_policy_route(policy, asn):
        '''
            {'color': 101,
            'endpoint': '7.7.7.7',
            'rate_bps': 20031882183,
            'router_id': '1.1.1.1',
            'samples': 6,
            'window_seconds': 49.4},
        '''
        # ipv4 router-id and endpoint
        flags = 0
        length = 24
        if ":" in policy["router_id"] and ":" in policy["endpoint"]:
            # ipv6 router-id and endpoint
            flags = 192
            length = 48
        elif ":" in policy["router_id"]:
            # ipv6 router-id, ipv4 endpoint
            flags = 64
            length = 36
        elif ":" in policy["endpoint"]:
            # ipv4 router-id, ipv6 endpoint
            flags = 128
            length = 36

        dummy_nlri = BgpAttribute.BgpLsNlri(BgpAttribute.BgpLsNlri.SR_POLICY, length)
        dummy_nlri.protocol_id = BgpAttribute.BgpLsNlri.SR
        dummy_nlri.identifier = 0

        sr_policy_route = BgpLsRoute(dummy_nlri)
        if not asn:
            asn = 0

        sr_policy_route.generate_sr_policy_nlri(asn, 0, policy["router_id"], 2, flags, policy["endpoint"], policy["color"])
        sr_policy_route.set_sr_policy_bandwidth(policy["rate_bps"])
        sr_policy_route.set_inserted()
        sr_policy_route.set_install_peer_list(["*"])

        return sr_policy_route


    def delete_policy(self, policy):
        self.logger.debug(f'Bgp: Generating BGP-LS route from policy router-id {policy["router_id"]}, endpoint {policy["endpoint"]}, color {policy["color"]}')
        sr_policy_route = self.generate_sr_policy_route(policy, self.asn)
        if not sr_policy_route.route_key:
            self.logger.error(f'Bgp: Unable to generate BGP-LS route from policy router-id {policy["router_id"]}, endpoint {policy["endpoint"]}, color {policy["color"]}')
            return
        self.logger.debug(f'Bgp: Successfully generated BGP-LS route {sr_policy_route.route_key}')

        self.logger.debug(f'Bgp: Deleting route {sr_policy_route.route_key} from LocRib link-state')
        self.LOC_RIBS["link-state"].delete_inserted_route_by_key(sr_policy_route.route_key)
        for neighbor_ip in self.neighbors.keys():
            negotiated_af = []
            for cap in self.neighbors[neighbor_ip].fsm.negotiated_capabilities:
                for k, v in BgpCapability.ADDRESS_FAMILIES.items():
                    if cap == v:
                        negotiated_af.append(k)
            if "link-state" in negotiated_af:
                self.logger.debug(f'Bgp: Withdrawing route {sr_policy_route.route_key} from AdjRibOut link-state for peer {neighbor_ip}')
                self.neighbors[neighbor_ip].RIB_OUTS["link-state"].delete_inserted_route_by_key(sr_policy_route)


    def update_policy(self, policy):
        self.logger.debug(f'Bgp: Generating BGP-LS route from policy router-id {policy["router_id"]}, endpoint {policy["endpoint"]}, color {policy["color"]}')
        sr_policy_route = self.generate_sr_policy_route(policy, self.asn)
        if not sr_policy_route.route_key:
            self.logger.error(f'Bgp: Unable to generate BGP-LS route from policy router-id {policy["router_id"]}, endpoint {policy["endpoint"]}, color {policy["color"]}')
            return
        self.logger.debug(f'Bgp: Successfully generated BGP-LS route {sr_policy_route.route_key}')

        self.logger.debug(f'Bgp: Inserting route {sr_policy_route.route_key} to LocRib link-state')
        self.LOC_RIBS["link-state"].insert_route(sr_policy_route)
        for neighbor_ip in self.neighbors.keys():
            negotiated_af = []
            for cap in self.neighbors[neighbor_ip].fsm.negotiated_capabilities:
                for k, v in BgpCapability.ADDRESS_FAMILIES.items():
                    if cap == v:
                        negotiated_af.append(k)
            if "link-state" in negotiated_af:
                self.logger.debug(f'Bgp: Inserting route {sr_policy_route.route_key} to AdjRibOut link-state for peer {neighbor_ip}')
                self.neighbors[neighbor_ip].RIB_OUTS["link-state"].insert_route(sr_policy_route)


    def update_logging_config(self, new_logging_config):
        self.logger.debug(f'Bgp: Updating logging config')
        logging.config.dictConfig(config=new_logging_config)
        formatter = HostnameFormatter(new_logging_config['formatters']['simple']['format'])
        for handler in logging.getLogger().handlers:
            handler.setFormatter(formatter)


    def return_keepalives(self):
        all_keepalives = {}
        all_keepalives["config_update_keepalive"] = self.config_update_keepalive
        all_keepalives["signal_receiver_keepalive"] = self.signal_receiver_keepalive
        for loc_rib_name, loc_rib in self.LOC_RIBS.items():
            all_keepalives[loc_rib_name] = loc_rib.rib_keepalive
        return all_keepalives


    def accept_incoming_connections(self, server):
        while True:
            sleep(0.1)
            if not self.running: continue
            conn, ip_address = server.accept()
            conn.setblocking(0)
            # without the following line eventlet throws exceptions when deleting bgp process
            #if len(self.neighbors) == 0: continue
            neighbor_ip = ip_address[0]

            if neighbor_ip not in self.neighbors.keys():
                self.logger.debug(f'Bgp: Rejected connection from {neighbor_ip} - neighbor not configured')
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
                # replaced return with continue here to avoid crashes when deleting neighbours
                # need more testing with multiple ipv4/ipv6 sessions
                #return
                continue

            if not self.neighbors[neighbor_ip].session:
                self.logger.debug(f'Bgp: Rejected connection from {neighbor_ip} - neighbor session inactive')
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
                continue

            if self.neighbors[neighbor_ip].session.admin_down:
                self.logger.debug(f'Bgp: Rejected connection from {neighbor_ip} - neighbor admin down')
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
                continue                

            self.logger.debug(f'Bgp: Accepting connection from {neighbor_ip}')
            self.neighbors[neighbor_ip].session.accept_connection(conn, ip_address)




    def run(self):
        if self.router_id and self.asn:
            self.running = True
            self.logger.info(f'Bgp: BGP server started')
        self.ipv4_server = listen(self.ipv4_address, socket.AF_INET)
        self.ipv6_server = listen(self.ipv6_address, socket.AF_INET6)

        for configured_neighbor in self.configured_neighbors:
            neighbor = BgpNeighbor(**configured_neighbor)
            self.neighbors[neighbor.remote_ip] = neighbor
            local_ip = neighbor.resolve_local_ip()
            neighbor.set_locals(local_ip, self.asn, self.router_id)
            neighbor.set_capabilities()
            neighbor.set_dynamics(self)


        if self.running:
            self.start_neighbors()
            for loc_rib_name, loc_rib in self.LOC_RIBS.items():
                self.running_ribs[loc_rib_name] = self.pool.spawn(loc_rib.process_route_changes)
        self.pool.spawn(self.update_config)  
        self.pool.spawn(self.receive_incoming_signal)
        self.pool.spawn(self.accept_incoming_connections, self.ipv4_server)
        self.pool.spawn(self.accept_incoming_connections, self.ipv6_server)
        self.pool.waitall()
  

