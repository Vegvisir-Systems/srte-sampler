#!/usr/bin/env python3

from pprint import pprint
from eventlet import GreenPool, listen, connect, greenthread, sleep
from eventlet.queue import Queue
from time import time
from datetime import timedelta

from .bgp_defaults import *
from .bgp_message import *
from .bgp_rib import *
from .bgp_route import *




class BgpFsm:
    def __init__(self, neighbor):
        self.neighbor = neighbor
        self.hold_timer = neighbor.hold_timer
        self.keepalive_timer = neighbor.keepalive_timer
        if self.keepalive_timer > self.hold_timer // 2:
            self.keepalive_timer = self.hold_timer // 3
        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Set Hold timer to {self.hold_timer}')
        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Set Keepalive timer to {self.keepalive_timer}')
        self.last_hold_timer = int(time())
        self.last_keepalive_timer = int(time())
        self.idle_hold_timer = BGP_IDLE_HOLD_TIMER
        self.connect_retry_timer = BGP_CONNECT_RETRY_TIMER
        self.last_idle_hold_timer = int(time())
        self.last_connect_retry_timer = int(time())
        self.last_up = None
        self.last_down = None
        self.last_state = "Idle"
        self.input_queue = Queue()
        self.output_queue = Queue()
        self.established_transitions = 0
        self.state = "Idle"
        self.negotiated_capabilities = []
        self.shutdown_requested = False

    KEEPALIVED_STATES = ["OpenSent", "OpenConfirm", "Established"]

    def set_keepalive_timer(self, keepalive_timer):
        self.keepalive_timer = keepalive_timer
        if self.keepalive_timer > self.hold_timer // 2:
            self.keepalive_timer = self.hold_timer // 3
        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Set Keepalive timer to {self.keepalive_timer}')

    def set_hold_timer(self, hold_timer):
        self.hold_timer = hold_timer
        if self.keepalive_timer > self.hold_timer // 2:
            self.keepalive_timer = self.hold_timer // 3
        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Set Hold timer to {self.hold_timer}')
        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Set Keepalive timer to {self.keepalive_timer}')

    def get_hold_time_left(self):
        if self.state in self.KEEPALIVED_STATES:
            return str(timedelta(seconds=self.hold_timer - (int(time()) - self.last_hold_timer)))
        return

    def get_keepalive_time_left(self):
        if self.state in self.KEEPALIVED_STATES:
            return str(timedelta(seconds=self.keepalive_timer - (int(time()) - self.last_keepalive_timer)))
        return
    
    def get_connect_retry_time_left(self):
        if self.state == "Active":
            return str(timedelta(seconds=self.connect_retry_timer - (int(time()) - self.last_connect_retry_timer)))
        return
    
    def get_idle_hold_time_left(self):
        if self.state == "Idle" and self.neighbor.session.admin_down is False:
            return str(timedelta(seconds=self.idle_hold_timer - (int(time()) - self.last_idle_hold_timer)))
        return
    
    def get_last_up_down(self):
        if self.state == "Established" and self.last_up:
            return str(timedelta(seconds=int(time()) - self.last_up))
        elif self.state != "Established" and self.last_down:
            return str(timedelta(seconds=int(time()) - self.last_down))
        return

    def message_received(self, message_type, message):
        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Received message type {BgpMessage.get_message_type(message_type)} in state {self.state}')
        if self.state == "Active" or self.state == "Connect":
            self.getmessage_active(message_type, message)
        elif self.state == "OpenSent":
            self.getmessage_opensent(message_type, message)
        elif self.state == "OpenConfirm":
            self.getmessage_openconfirm(message_type, message)
        elif self.state == "Established":
            self.getmessage_established(message_type, message)

    def process_bgp_open(self, message):
        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Processing BGP Open...')
        self.negotiated_capabilities = []
        # this can lead to BGP session being established if neighbor has AS set as 23456 and doesn't support ASN32
        if message.asn != self.neighbor.remote_as and message.asn != 23456:
            self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Received Open message with bad ASN {message.asn}')
            self.neighbor.session.drop_session(BgpNotification.OPEN_MESSAGE_ERROR, BgpNotification.BAD_PEER_AS)
            return
        if message.router_id == self.neighbor.local_router_id:
            self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Received Open message with our local Router ID')
            self.neighbor.session.drop_session(BgpNotification.OPEN_MESSAGE_ERROR, BgpNotification.BAD_BGP_IDENTIFIER)
            return
        if message.hold_timer < self.hold_timer:
            self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Adjusting Hold timer based on received Open message')
            self.hold_timer = message.hold_timer
            self.keepalive_timer = self.hold_timer // 3
            self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Set Hold timer to {self.hold_timer}')
            self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Set Keepalive timer to {self.keepalive_timer}')
        self.neighbor.remote_router_id = message.router_id
        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Parsing capabilities...')
        for cap in message.capabilities:
            if cap in self.neighbor.capabilities and cap["code"] != BgpCapability.ASN32:
                if cap not in self.negotiated_capabilities:
                    self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Negotiated capability {cap["code"]}')
                    if cap["code"] == BgpCapability.MP_EXTENSIONS:
                        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Negotiated af {cap["value"]}')
                    self.negotiated_capabilities.append(cap)
            elif cap["code"] == BgpCapability.ASN32 and self.neighbor.asn32_support:
                if cap["value"] != self.neighbor.remote_as:
                    self.neighbor.logger.error(f'Bgp neighbor {self.neighbor.remote_ip}: Received ASN32 capability with bad ASN {cap["value"]}')
                    self.neighbor.session.drop_session(BgpNotification.OPEN_MESSAGE_ERROR, BgpNotification.BAD_PEER_AS)
                    return
                self.negotiated_capabilities.append(cap)
        # drop session if no AF have been negotiated
        af_negotiated = False
        for cap in self.negotiated_capabilities:
            if cap in BgpCapability.ADDRESS_FAMILIES.values():
                af_negotiated = True
                break
        if not af_negotiated:
            self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Dropping session because no AF have been negotiated')
            self.neighbor.session.drop_session(BgpNotification.OPEN_MESSAGE_ERROR, BgpNotification.UNSUPPORTED_CAPABILITY)

    def process_bgp_update(self, message):
        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Processing BGP update')

        acceptable_af = []
        for af in BgpCapability.ADDRESS_FAMILIES.values():
            if af in self.negotiated_capabilities:
                acceptable_af.append(af["value"])
        
        path_attributes = {}
        nlris = []
        withdrawn_nlris = []
        link_state_tlvs = []
        afi = None
        safi = None
        remote_router_id_override = None

        def process_origin(attr):
            path_attributes["origin"] = attr.origin
            self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Received ORIGIN set to {path_attributes["origin"]}')
            
        def process_as_path(attr):
            path_attributes["as_path"] = attr.as_path
            self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Received AS_PATH set to {path_attributes["as_path"]}')
            
        def process_next_hop(attr):
            path_attributes["next_hop"] = attr.next_hop
            self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Received NEXT_HOP set to {path_attributes["next_hop"]}')
            
        def process_multi_exit_disc(attr):
            path_attributes["multi_exit_disc"] = attr.multi_exit_disc
            self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Received MULTI_EXIT_DISC set to {path_attributes["multi_exit_disc"]}')

        def process_local_pref(attr):
            path_attributes["local_pref"] = attr.local_pref
            self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Received LOCAL_PREF set to {path_attributes["local_pref"]}')

        def process_originator_id(attr):
            path_attributes["originator_id"] = attr.originator_id
            self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Received ORIGINATOR_ID set to {path_attributes["originator_id"]}')

        def process_cluster_list(attr):
            path_attributes["cluster_list"] = attr.cluster_list
            self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Received CLUSTER_LIST set to {path_attributes["cluster_list"]}')

        def process_community(attr):
            pass

        def process_large_community(attr):
            nonlocal remote_router_id_override
            if attr.asn != self.neighbor.remote_as:
                self.neighbor.logger.error(f'Bgp neighbor {self.neighbor.remote_ip}: Received Large Community with ASN {attr.asn} not equal to peer ASN {self.neighbor.remote_as}')
                return
            # router ID override
            self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Received Large Community {attr.local_data1}:{attr.local_data2}')
            if attr.local_data1 == 1:
                ip_bin = struct.pack("!L", attr.local_data2)
                remote_router_id_override = ip_to_string(ip_bin)
                self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Processed Large Community as remote router-id override to {remote_router_id_override}')
            else:
                self.neighbor.logger.error(f'Bgp neighbor {self.neighbor.remote_ip}: Unable to process Large Community with unknown local_data {attr.local_data1}')

        def process_mp_reach_nlri(attr):
            nonlocal afi
            nonlocal safi
            afi, safi = attr.afi, attr.safi
            if (afi, safi) not in acceptable_af:
                self.neighbor.logger.error(f'Bgp neighbor {self.neighbor.remote_ip}: Received MP_REACH_NLRI with not negotiated AFI {attr.afi}, SAFI {attr.safi}')
                return
            path_attributes["next_hop"] = attr.next_hop
            if afi == BgpCapability.BgpAfi.LS and safi == BgpCapability.BgpSafi.LS:
                for nlri in attr.bgp_ls_nlris:
                    self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Processing MP_REACH_NLRI for BGP_LS')
                    nlris.append(nlri)

            
        def process_mp_unreach_nlri(attr):
            nonlocal afi
            nonlocal safi
            afi, safi = attr.afi, attr.safi
            if (afi, safi) not in acceptable_af:
                self.neighbor.logger.error(f'Bgp neighbor {self.neighbor.remote_ip}: Received MP_UNREACH_NLRI with not negotiated AFI {attr.afi}, SAFI {attr.safi}')
                return
            if afi == BgpCapability.BgpAfi.LS and safi == BgpCapability.BgpSafi.LS:
                for nlri in attr.bgp_ls_nlris:
                    self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Processing MP_UNREACH_NLRI for BGP_LS')
                    withdrawn_nlris.append(nlri)
               

        def process_extended_community(attr):
            pass

        def process_tunnel_encap(attr):
            pass
        
        def process_bgp_ls(attr):
            self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Processing BGP_LS_ATTRIBUTE')
            for tlv in attr.link_state_tlvs:
                link_state_tlvs.append(tlv)
            

        functions = {
            BgpAttribute.ORIGIN: process_origin,
            BgpAttribute.AS_PATH: process_as_path,
            BgpAttribute.NEXT_HOP: process_next_hop,
            BgpAttribute.MULTI_EXIT_DISC: process_multi_exit_disc,
            BgpAttribute.LOCAL_PREF: process_local_pref,
            BgpAttribute.ORIGINATOR_ID: process_originator_id,
            BgpAttribute.CLUSTER_LIST: process_cluster_list,
            BgpAttribute.COMMUNITY: process_community,
            BgpAttribute.LARGE_COMMUNITY: process_large_community,
            BgpAttribute.MP_REACH_NLRI: process_mp_reach_nlri,
            BgpAttribute.MP_UNREACH_NLRI: process_mp_unreach_nlri,
            BgpAttribute.EXT_COMMUNITIES: process_extended_community,
            BgpAttribute.TUNNEL_ENCAP: process_tunnel_encap,
            BgpAttribute.BGP_LS: process_bgp_ls
        }
        
        for attr in message.path_attributes:
            try:
                func = functions[attr.type_code]
                func(attr)
            except KeyError:
                self.neighbor.logger.error(f'Bgp neighbor {self.neighbor.remote_ip}: Unknown attribute type code {attr.type_code}')

        for nlri in nlris:
            if afi == BgpCapability.BgpAfi.LS and safi == BgpCapability.BgpSafi.LS:
                try:
                    route = BgpLsRoute(nlri)
                    route.process_nlri(nlri)
                    route.set_peer_details(self.neighbor.remote_router_id, self.neighbor.remote_ip, self.neighbor.remote_as, self.neighbor.link_type)
                    route.apply_path_attributes(**path_attributes)
                    route.apply_bgp_ls_attribute(link_state_tlvs)
                    if route.route_key:
                        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Adding BGP_LS route {route.route_key} to LS AdjRibIn')
                        self.neighbor.ls_adj_rib_in.add_route(route)
                except:
                    self.neighbor.logger.exception(f'Bgp neighbor {self.neighbor.remote_ip}: Unable to process received BGP-LS NLRI')



        for withdrawn_nlri in withdrawn_nlris:
            if afi == BgpCapability.BgpAfi.LS and safi == BgpCapability.BgpSafi.LS:
                try:
                    route = BgpLsRoute(withdrawn_nlri)
                    route.process_nlri(withdrawn_nlri)
                    route.set_peer_details(self.neighbor.remote_router_id, self.neighbor.remote_ip, self.neighbor.remote_as, self.neighbor.link_type)
                    if route.route_key:
                        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Deleting BGP_LS route {route.route_key} from LS AdjRibIn')
                        self.neighbor.ls_adj_rib_in.del_route(route.route_key)
                except:
                    self.neighbor.logger.exception(f'Bgp neighbor {self.neighbor.remote_ip}: Unable to withdraw BGP-LS NLRI')


    def process_bgp_route_refresh(self, message):
        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Received route refresh for {message.afi}, {message.safi}')
        if BgpCapability.OTHER_CAPABILITIES['route-refresh'] not in self.negotiated_capabilities: return
        for af_name, af in BgpCapability.ADDRESS_FAMILIES.items():
            if af not in self.negotiated_capabilities: continue
            if af["value"] != (message.afi, message.safi): continue
            if not self.neighbor.RIB_OUTS[af_name]: continue
            self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Refreshing AdjRibOut for AF {af_name}')
            self.neighbor.RIB_OUTS[af_name].refresh_all_routes()
            self.neighbor.RIB_OUTS[af_name].advertise_routes()



    def process_bgp_notification(self, message):
        self.neighbor.logger.warning(f'Bgp neighbor {self.neighbor.remote_ip}: Received Notification, code {BgpNotification.get_error_code(message.error_code)} / subcode {BgpNotification.get_error_subcode(message.error_code, message.error_subcode)}')
        self.neighbor.session.drop_session()

    def getmessage_active(self, message_type, message):
        if message_type != BgpMessage.OPEN:
            self.neighbor.logger.error(f'Bgp neighbor {self.neighbor.remote_ip}: Received bad message type {BgpMessage.get_message_type(message_type)} in Active state')
            self.neighbor.session.drop_session(BgpNotification.FINITE_STATE_MACHINE_ERROR, 0)
            return
        self.process_bgp_open(message)
        self.last_hold_timer = int(time())
        self.last_state = self.state
        self.neighbor.logger.info(f'Bgp neighbor {self.neighbor.remote_ip}: Old state {self.state} new state OpenConfirm')
        self.state = "OpenConfirm"
        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Sent Open')
        if self.neighbor.local_as > 65535:
            self.output_queue.put(BgpOpen(4, 23456, self.hold_timer, self.neighbor.local_router_id, self.neighbor.capabilities))
        else:
            self.output_queue.put(BgpOpen(4, self.neighbor.local_as, self.hold_timer, self.neighbor.local_router_id, self.neighbor.capabilities))
        self.output_queue.put(BgpKeepalive)
        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Sent Keepalive')

    def getmessage_opensent(self, message_type, message):
        if message_type == BgpMessage.OPEN:
            self.last_hold_timer = int(time())
            self.process_bgp_open(message)
            if self.state == "OpenSent":
                self.last_state = self.state
                self.neighbor.logger.info(f'Bgp neighbor {self.neighbor.remote_ip}: Old state {self.state} new state OpenConfirm')
                self.state = "OpenConfirm"
                self.output_queue.put(BgpKeepalive)
                self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Sent Keepalive')   
        elif message_type == BgpMessage.NOTIFICATION:
            self.process_bgp_notification(message)
        else:
            self.neighbor.logger.error(f'Bgp neighbor {self.neighbor.remote_ip}: Received bad message type {BgpMessage.get_message_type(message_type)} in OpenSent state')
            self.neighbor.session.drop_session(BgpNotification.FINITE_STATE_MACHINE_ERROR, BgpNotification.UNEXPECTED_MESSAGE_OPENSENT_STATE)
            
    def getmessage_openconfirm(self, message_type, message):
        if message_type == BgpMessage.KEEPALIVE:
            self.last_hold_timer = int(time())
            self.neighbor.logger.info(f'Bgp neighbor {self.neighbor.remote_ip}: Old state {self.state} new state Established')
            self.last_state = self.state
            self.state = "Established"
            self.last_up = int(time())
            self.established_transitions += 1
            # once established, fetch relevant routes from LocRib to AdjRibOut
            for af_name, af in BgpCapability.ADDRESS_FAMILIES.items():
                if af not in self.negotiated_capabilities: continue
                if not self.neighbor.RIB_OUTS[af_name]: continue
                self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Fetching routes from LocRib to AdjRibOut for AF {af_name}')
                self.neighbor.RIB_OUTS[af_name].fetch_routes_from_loc_rib()
        elif message_type == BgpMessage.NOTIFICATION:
            self.process_bgp_notification(message)
        else:
            self.neighbor.logger.error(f'Bgp neighbor {self.neighbor.remote_ip}: Received bad message type {BgpMessage.get_message_type(message_type)} in OpenConfirm state')
            self.neighbor.session.drop_session(BgpNotification.FINITE_STATE_MACHINE_ERROR, BgpNotification.UNEXPECTED_MESSAGE_OPENCONFIRM_STATE)

    def getmessage_established(self, message_type, message):
        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor.remote_ip}: Received message type {BgpMessage.get_message_type(message_type)} in Established state')
        if message_type == BgpMessage.KEEPALIVE:
            self.last_hold_timer = int(time())
        elif message_type == BgpMessage.NOTIFICATION:
            self.process_bgp_notification(message)
        elif message_type == BgpMessage.UPDATE:
            self.last_hold_timer = int(time())
            self.process_bgp_update(message)
        elif message_type == BgpMessage.ROUTE_REFRESH:
            self.last_hold_timer = int(time())
            self.process_bgp_route_refresh(message)
