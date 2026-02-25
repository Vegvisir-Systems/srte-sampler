#!/usr/bin/env python3
from pprint import pprint

from eventlet import GreenPool, listen, connect, greenthread, sleep, semaphore
from eventlet.queue import Queue
import socket
import struct
import copy
from time import time


from .bgp_defaults import *
from .bgp_message import *


def ip_to_string(ip_address_bin):
    return socket.inet_ntop(socket.AF_INET, ip_address_bin)

def string_to_ip(ip_address_str):
    return socket.inet_pton(socket.AF_INET, ip_address_str)

def ip6_to_string(ip_address_bin):
    return socket.inet_ntop(socket.AF_INET6, ip_address_bin)

def string_to_ip6(ip_address_str):
    return socket.inet_pton(socket.AF_INET6, ip_address_str)


class BgpAdjRibIn:
    def __init__(self, neighbor, afi, safi, loc_rib, logger):
        self.neighbor = neighbor
        self.afi = afi
        self.safi = safi
        self.loc_rib = loc_rib
        self.rib = {}
        self.logger = logger


    def add_route(self, route):
        self.logger.debug(f'Bgp AdjRibIn for neighbor {self.neighbor.remote_ip} {self.afi} / SAFI {self.safi}: Adding route {route.route_key}')
        if route.originator_id:
            if self.neighbor.bgp_server.router_id == route.originator_id:
                self.logger.warning(f'Bgp AdjRibIn for neighbor {self.neighbor.remote_ip} {self.afi} / SAFI {self.safi}: Received route {route.route_key} with ORIGINATOR_ID {route.originator_id} same as local router-id')
        self.rib[route.route_key] = route
        self.loc_rib.queue_add_route(route)


    def del_route(self, route_key):
        self.logger.debug(f'Bgp AdjRibIn for neighbor {self.neighbor.remote_ip} {self.afi} / SAFI {self.safi}: Deleting route {route_key}')
        if route_key in self.rib.keys():
            self.loc_rib.queue_del_route(self.rib[route_key])
            del self.rib[route_key]


    def del_all_routes(self):
        self.logger.debug(f'Bgp AdjRibIn for neighbor {self.neighbor.remote_ip} {self.afi} / SAFI {self.safi}: Deleting all routes')
        delete_routes = list(self.rib.keys())
        for route_key in delete_routes:
            self.del_route(route_key)


    def return_received_nlri_count(self):
        return len(self.rib)


class BgpAdjRibOut:
    def __init__(self, neighbor, afi, safi, loc_rib, logger):
        self.neighbor = neighbor
        self.afi = afi
        self.safi = safi
        self.loc_rib = loc_rib
        self.rib = {}
        self.update_queue = Queue()
        self.withdraw_queue = Queue()
        self.logger = logger


    def insert_route(self, route):
        self.logger.debug(f'Bgp AdjRibOut for neighbor {self.neighbor.remote_ip} {self.afi} / SAFI {self.safi}: Inserting route {route.route_key}')
        self.rib[route.route_key] = route
        self.update_queue.put(route)
        self.advertise_routes()


    def delete_inserted_route_by_key(self, route_key):
        self.logger.debug(f'Bgp AdjRibOut for neighbor {self.neighbor.remote_ip} {self.afi} / SAFI {self.safi}: Deleting inserted route {route_key}')
        if route_key in self.rib.keys():
            self.withdraw_queue.put(self.rib[route_key])
            del self.rib[route_key]
            self.advertise_routes()


    def fetch_routes_from_loc_rib(self):
        self.logger.debug(f'Bgp AdjRibOut for neighbor {self.neighbor.remote_ip} {self.afi} / SAFI {self.safi}: Fetching routes from LocRib')
        for inserted_route_key, candidate_paths in self.loc_rib.rib.items():
            for path in candidate_paths:
                if path.inserted:
                    if self.neighbor.remote_ip in path.install_peer_list or "*" in path.install_peer_list:
                        self.logger.debug(f'Bgp AdjRibOut for neighbor {self.neighbor.remote_ip} {self.afi} / SAFI {self.safi}: Fetched route {inserted_route_key} from LocRib')
                        self.rib[path.route_key] = path
                        self.update_queue.put(path)
        self.advertise_routes()


    def refresh_all_routes(self):
        for route in self.rib.values():
            self.update_queue.put(route)
          

    def pack_ls_route(self, route):
        self.logger.debug(f'Bgp AdjRibOut for neighbor {self.neighbor.remote_ip} {self.afi} / SAFI {self.safi}: Packing LS advertisement for {route.route_key}')
        path_attributes = []

        origin = BgpAttribute(False, True, False, False, BgpAttribute.ORIGIN, 1)
        origin.set_origin(0)
        path_attributes.append(origin)
        
        if self.neighbor.link_type == "external":
            asn32_support = False
            for cap in self.neighbor.fsm.negotiated_capabilities:
                if BgpCapability.OTHER_CAPABILITIES["asn32"]["code"] == cap["code"]:
                    asn32_support = True
            if asn32_support:
                as_path = BgpAttribute(False, True, False, False, BgpAttribute.AS_PATH, 6)
                as_path.set_as_path([], [self.neighbor.local_as], True)
            else:
                as_path = BgpAttribute(False, True, False, False, BgpAttribute.AS_PATH, 4)
                if self.neighbor.local_asn32:
                    as_path.set_as_path([], [23456])
                else:
                    as_path.set_as_path([], [self.neighbor.local_as])
            path_attributes.append(as_path)
        else:
            as_path = BgpAttribute(False, True, False, False, BgpAttribute.AS_PATH, 2)
            as_path.set_as_path([], [])
            path_attributes.append(as_path)
            local_pref = BgpAttribute(False, True, False, False, BgpAttribute.LOCAL_PREF, 4)
            local_pref.set_local_pref(100)
            path_attributes.append(local_pref)


        ls_nlri = BgpAttribute.BgpLsNlri(BgpAttribute.BgpLsNlri.SR_POLICY, 0)
        ls_nlri.protocol_id = BgpAttribute.BgpLsNlri.SR
        ls_nlri.identifier = 0
        ls_nlri.set_bgp_ls_sr_policy_nlri(route.autonomous_system, route.bgp_ls_id, route.bgp_router_id, route.bgp_router_id, route.protocol_origin, route.sr_policy_flags, route.sr_policy_endpoint, route.sr_policy_color)
        # set length to 0 for MP_REACH_NLRI; actual length will be calculated during message generation
        mp_reach_nlri = BgpAttribute(True, False, False, False, BgpAttribute.MP_REACH_NLRI, 0)
        if ":" in self.neighbor.local_ip:
            next_hop_length = 16
        else:
            next_hop_length = 4
        mp_reach_nlri.set_mp_reach_nlri(self.afi, self.safi, next_hop_length, self.neighbor.local_ip, ls_nlri)
        path_attributes.append(mp_reach_nlri)

        bgp_ls_attribute = BgpAttribute(True, True, False, False, BgpAttribute.BGP_LS, 0)
        bgp_ls_attribute.set_sr_policy_bgp_ls_attribute(route.bandwidth_rate_bps)
        path_attributes.append(bgp_ls_attribute)


        return path_attributes
    

    def pack_ls_withdraw(self, route):
        self.logger.debug(f'Bgp AdjRibOut for neighbor {self.neighbor.remote_ip} {self.afi} / SAFI {self.safi}: Packing LS withdraw for {route.route_key}')
        path_attributes = []
        ls_nlri = BgpAttribute.BgpLsNlri(BgpAttribute.BgpLsNlri.SR_POLICY, 0)
        ls_nlri.protocol_id = BgpAttribute.BgpLsNlri.SR
        ls_nlri.identifier = 0
        ls_nlri.set_bgp_ls_sr_policy_nlri(route.autonomous_system, route.bgp_ls_id, route.bgp_router_id, route.bgp_router_id, route.protocol_origin, route.sr_policy_flags, route.sr_policy_endpoint, route.sr_policy_color)
        # set length to 0 for MP_UNREACH_NLRI; actual length will be calculated during message generation
        mp_unreach_nlri = BgpAttribute(True, False, False, False, BgpAttribute.MP_UNREACH_NLRI, 0)
        mp_unreach_nlri.set_mp_unreach_nlri(self.afi, self.safi, ls_nlri)
        path_attributes.append(mp_unreach_nlri)
        return path_attributes
    

    def advertise_routes(self):
        self.logger.debug(f'Bgp AdjRibOut for neighbor {self.neighbor.remote_ip} {self.afi} / SAFI {self.safi}: Advertising NLRI from update queue')
        while self.update_queue.qsize():
            try:
                path_attributes = None
                route = self.update_queue.get()
                if self.safi == BgpCapability.BgpSafi.LS:
                    path_attributes = self.pack_ls_route(route)
                if not path_attributes:
                    self.logger.error(f'Bgp AdjRibOut for neighbor {self.neighbor.remote_ip} {self.afi} / SAFI {self.safi}: Unable to pack BGP path attributes to advertise route {route.route_key}')
                    continue
                self.neighbor.fsm.output_queue.put(BgpUpdate(0, None, 0, path_attributes))
            except Exception as e:
                self.logger.error(f'Bgp AdjRibOut for neighbor {self.neighbor.remote_ip} {self.afi} / SAFI {self.safi}: unable to advertise route {route.route_key}, exception {e.__class__.__name__, e.args}')
        self.logger.debug(f'Bgp AdjRibOut for neighbor {self.neighbor.remote_ip} {self.afi} / SAFI {self.safi}: Advertising NLRI from withdraw queue')
        while self.withdraw_queue.qsize():
            try:
                path_attributes = None
                route = self.withdraw_queue.get()
                if self.safi == BgpCapability.BgpSafi.LS:
                    path_attributes = self.pack_ls_withdraw(route)
                if not path_attributes:
                    self.logger.error(f'Bgp AdjRibOut for neighbor {self.neighbor.remote_ip} {self.afi} / SAFI {self.safi}: Unable to pack BGP path attributes to withdraw route {route.route_key}')
                    continue
                self.neighbor.fsm.output_queue.put(BgpUpdate(0, None, 0, path_attributes))
            except Exception as e:
                self.logger.error(f'Bgp AdjRibOut for neighbor {self.neighbor.remote_ip} {self.afi} / SAFI {self.safi}: unable to withdraw route {route.route_key}, exception {e.__class__.__name__, e.args}')
    

    def reset_rib(self):
        self.rib = {}
        self.update_queue = Queue()
        self.withdraw_queue = Queue()
       

    def return_sent_nlri_count(self):
        return len(self.rib)
    


class BgpLocRib:
    def __init__(self, afi, safi, logger):
        self.afi = afi
        self.safi = safi
        self.rib = {}
        self.update_route_queue = Queue()
        self.init_time = round(time()*1000)
        self.measuring = False
        self.measured = False
        self.logger = logger
        self.rib_keepalive = 0


    def best_path(self, paths):
        # optimized version of best_path
        #0. Locally inserted route always wins
        #1. WEIGHT
        #2. LOCAL_PREF
        #3. AS_PATH
        #4. ORIGIN
        #5. MED (if from same AS)
        #6. eBGP over iBGP
        #7. lower router id
        #8. lower remote ip
        #9. oldest
        candidate_paths = copy.deepcopy(paths)

        self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Best Path - checking if any route is locally inserted')

        for route in candidate_paths:
            if route.inserted:
                return route, "Inserted route exists"

        self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Best Path - checking WEIGHT')

        max_weight = max(route.weight for route in candidate_paths)
        candidate_paths = [route for route in candidate_paths if route.weight == max_weight]

        if len(candidate_paths) == 1:
            return candidate_paths[0], "Weight"

        self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Best Path - checking LOCAL_PREF')

        max_local_pref = max(route.local_pref for route in candidate_paths)
        candidate_paths = [route for route in candidate_paths if route.local_pref == max_local_pref]

        if len(candidate_paths) == 1:
            return candidate_paths[0], "Local Pref"
        
        self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Best Path - checking AS_PATH')

        shortest_as_path = min(route.as_path_length for route in candidate_paths)
        candidate_paths = [route for route in candidate_paths if route.as_path_length == shortest_as_path]

        if len(candidate_paths) == 1:
            return candidate_paths[0], "AS Path"
        
        self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Best Path - checking ORIGIN')

        lowest_origin = min(route.origin for route in candidate_paths)
        candidate_paths = [route for route in candidate_paths if route.origin == lowest_origin]
            
        if len(candidate_paths) == 1:
            return candidate_paths[0], "Higher origin"
        
        self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Best Path - checking MULTI_EXIT_DISC')

        # use MED when all routes from same AS 
        remote_as_set = {route.remote_as for route in candidate_paths}
        if len(remote_as_set) == 1:
            lowest_med = min(route.multi_exit_disc for route in candidate_paths)
            candidate_paths = [route for route in candidate_paths if route.multi_exit_disc == lowest_med]
        
        if len(candidate_paths) == 1:
            return candidate_paths[0], "Higher MED"
        
        self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Best Path - checking eBGP vs iBGP')

        if any(route.link_type == "external" for route in candidate_paths):
            candidate_paths = [route for route in candidate_paths if route.link_type == "external"]
        
        if len(candidate_paths) == 1:
            return candidate_paths[0], "iBGP loses to eBGP"
        
        self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Best Path Tie Break - checking ROUTER_ID')

        lowest_router_id = min(route.remote_router_id for route in candidate_paths)
        candidate_paths = [route for route in candidate_paths if route.remote_router_id == lowest_router_id]


        if len(candidate_paths) == 1:
            return candidate_paths[0], "Higher router ID"
        
        self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Best Path Tie Break - checking NEXT_HOP')

        lowest_remote_ip = b"\xff" * 4
        lowest_remote_ipv6 = b"\xff" * 16
        for route in candidate_paths:
            if ":" in route.remote_ip:
                if string_to_ip6(route.remote_ip) < lowest_remote_ipv6:
                    lowest_remote_ipv6 = string_to_ip6(route.remote_ip)
            else:
                if string_to_ip(route.remote_ip) < lowest_remote_ip:
                    lowest_remote_ip = string_to_ip(route.remote_ip)
        for route in candidate_paths:
            if ":" in route.remote_ip:
                if string_to_ip6(route.remote_ip) > lowest_remote_ipv6:
                    candidate_paths.remove(route)
            else:
                if string_to_ip(route.remote_ip) > lowest_remote_ip:
                    candidate_paths.remove(route)
        
        # if both ipv4 and ipv6 nexthops are present among candidates - ipv4 wins
        if lowest_remote_ip != b"\xff" * 4 and lowest_remote_ipv6 != b"\xff" * 16:
            for route in candidate_paths:
                if ":" in route.remote_ip:
                    candidate_paths.remove(route)

        if len(candidate_paths) == 1:
            return candidate_paths[0], "Higher IP"
        
        self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Best Path Tie Break - Returning older route')
        
        return candidate_paths[0], "Older route exists"




    def add_route(self, route):
        route.last_modified = int(time())
        if route.route_key not in self.rib.keys():
            self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Adding new route {route.route_key}')
            route.best = True
            self.rib[route.route_key] = []        
            self.rib[route.route_key].append(route)
            if not self.measuring:
                self.measuring = True
                self.init_time = round(time()*1000)
            if len(self.rib) >= 50000 and self.measuring and not self.measured:
                print(f'Loaded 50k routes in {round(time()*1000) - self.init_time} miliseconds')
                self.measured = True
                self.measuring = False
        else:
            for item in self.rib[route.route_key]:
                if item.remote_ip == route.remote_ip:
                    self.rib[route.route_key].remove(item)
            self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Updating route {route.route_key}')
            self.rib[route.route_key].append(route)
            self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Running best path algorithm for route {route.route_key}')
            best_route, reason_not_best = self.best_path(self.rib[route.route_key])
            for item in self.rib[route.route_key]:
                if item.remote_ip == best_route.remote_ip:
                    self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Route {route.route_key} from {best_route.remote_ip} is Best')
                    item.best = True
                else:
                    item.best = False
                    item.reason_not_best = reason_not_best
            if not self.measuring:
                self.measuring = True
                self.init_time = round(time()*1000)
            if len(self.rib) >= 50000 and self.measuring and not self.measured:
                print(f'Loaded 50k routes in {round(time()*1000) - self.init_time} miliseconds')
                self.measured = True
                self.measuring = False
            if best_route.inserted:
                self.logger.error(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: When adding new route {route.route_key} found an existing inserted route for the same NLRI. Please make sure LU EPE routes do not conflict with LU policies')


    def del_route(self, route):
        if route.route_key in self.rib.keys():
            for item in self.rib[route.route_key]:
                if item.remote_ip == route.remote_ip:
                    self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Removing route {route.route_key}')
                    self.rib[route.route_key].remove(item)
                    # if this was the last path - delete route
                    if len(self.rib[route.route_key]) == 0:
                        del self.rib[route.route_key]
                        return
            self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Running best path algorithm for route {route.route_key}')
            best_route, reason_not_best = self.best_path(self.rib[route.route_key])
            for item in self.rib[route.route_key]:
                if item.remote_ip == best_route.remote_ip:
                    self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Route {route.route_key} from {best_route.remote_ip} is Best')
                    item.best = True
                else:
                    item.best = False
                    item.reason_not_best = reason_not_best



    def insert_route(self, route):
        route.origin = 0
        route.last_modified = int(time())
        self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Inserting new route {route.route_key}')
        if route.route_key in self.rib.keys():
            for item in self.rib[route.route_key]:
                if not item.inserted:
                    self.logger.error(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: When inserting new route {route.route_key} found an existing non-inserted route for the same NLRI. Please make sure LU EPE routes do not conflict with LU policies')
                    item.best = False
                    item.reason_not_best = "Inserted route exists"
                else:
                    self.rib[route.route_key].remove(item)
        else:
            self.rib[route.route_key] = []
        route.best = True
        self.rib[route.route_key].append(route)

    
    def delete_inserted_route_by_key(self, route_key):
        self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Deleting inserted route {route_key}')
        if route_key not in self.rib.keys(): return
        if len(self.rib[route_key]) > 1:
            self.logger.error(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: When deleting inserted route {route_key} found an existing non-inserted route for the same NLRI. Please make sure LU EPE routes do not conflict with LU policies')
            for item in self.rib[route_key]:
                if item.inserted:
                    self.rib[route_key].remove(item)
            self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Running best path algorithm for route {route_key}')
            best_route, reason_not_best = self.best_path(self.rib[route_key])
            for item in self.rib[route_key]:
                if item.remote_ip == best_route.remote_ip:
                    self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Route {route_key} from {best_route.remote_ip} is Best')
                    item.best = True
                else:
                    item.best = False
                    item.reason_not_best = reason_not_best
        else:
            del self.rib[route_key]
        
    
    def queue_add_route(self, route):
        self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Adding route {route.route_key} to Update queue')
        self.update_route_queue.put(("add", route))
    
    def queue_del_route(self, route):
        self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Adding route {route.route_key} to Delete queue')
        self.update_route_queue.put(("del", route))

    
    def process_route_changes(self):
        while True:
            sleep(0.01)
            if int(time()) > self.rib_keepalive:
                self.rib_keepalive = int(time())
            if not self.update_route_queue.qsize(): continue
            init_time = round(time()*1000)
            while self.update_route_queue.qsize():
                self.logger.debug(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Fetching routes from Update/Delete queue')
                if round(time()*1000) - init_time > 500: 
                    break
                try:
                    action, route = self.update_route_queue.get()
                    if action == "add":
                        self.add_route(route)
                    elif action == "del":
                        self.del_route(route)
                    else: continue
                except:
                    self.logger.exception(f'Bgp LocRib AFI {self.afi} / SAFI {self.safi}: Failed to process LocRib route update')

