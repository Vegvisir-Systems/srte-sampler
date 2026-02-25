#!/usr/bin/env python3

from pprint import pprint
from time import time
from datetime import timedelta
import copy

from .bgp_message import *

class ShowBgpResponder:
    def __init__(self, bgp_server):
        self.bgp_server = bgp_server


    def bgp_summary(self):
        self.bgp_server.logger.debug(f'Bgp show responder: Sending BGP summmary info')
        bgp_summary = {}
        bgp_summary["router_id"] = self.bgp_server.router_id
        bgp_summary["asn"] = self.bgp_server.asn
        bgp_summary["peers"] = {}
        for neighbor, neighbor_state in self.bgp_server.neighbors.items():
            peer_dict = {}
            peer_dict["description"] = neighbor_state.description
            peer_dict["msg_sent"] = neighbor_state.counters.return_out_msg_stats_summary()
            peer_dict["in_msg_queue"] = neighbor_state.fsm.input_queue.qsize()
            peer_dict["last_up_down"] = neighbor_state.fsm.get_last_up_down()
            peer_dict["version"] = 4
            peer_dict["msg_received"] = neighbor_state.counters.return_in_msg_stats_summary()
            peer_dict["peer_state"] = neighbor_state.fsm.state
            peer_dict["admin_down"] = neighbor_state.session.admin_down
            peer_dict["pfx_limit_exceeded"] = neighbor_state.session.pfx_limit_exceeded
            peer_dict["out_msg_queue"] = neighbor_state.fsm.output_queue.qsize()
            peer_dict["asn"] = neighbor_state.remote_as
            peer_dict["address_families"] = []
            for cap in neighbor_state.fsm.negotiated_capabilities:
                for k, v in BgpCapability.ADDRESS_FAMILIES_SHORT.items():
                    if cap == v:
                        peer_dict["address_families"].append(k)
                peer_dict["address_families"].sort()
            peer_dict["nlri_received"] = neighbor_state.return_received_nlri_count()
            bgp_summary["peers"][neighbor] = peer_dict
        return bgp_summary


    def bgp_neighbor_detail(self, queried_neighbor):
        self.bgp_server.logger.debug(f'Bgp show responder: Sending BGP neighbor info for {queried_neighbor}')
        peer_dict = {}
        try:
            peer_dict["description"] = self.bgp_server.neighbors[queried_neighbor].description
            peer_dict["link_type"] = self.bgp_server.neighbors[queried_neighbor].link_type
            peer_dict["config_remote_port"] = self.bgp_server.neighbors[queried_neighbor].session.neighbor_port
            peer_dict["passive"] = self.bgp_server.neighbors[queried_neighbor].passive
            peer_dict["drop_stats"] = None
            peer_dict["peer_address"] = queried_neighbor
            peer_dict["local_address"] = self.bgp_server.neighbors[queried_neighbor].local_ip
            peer_dict["asn"] = self.bgp_server.neighbors[queried_neighbor].remote_as
            peer_dict["local_asn"] = self.bgp_server.neighbors[queried_neighbor].local_as
            peer_dict["router_id"] = self.bgp_server.neighbors[queried_neighbor].remote_router_id
            peer_dict["local_router_id"] = self.bgp_server.neighbors[queried_neighbor].local_router_id
            peer_dict["negotiated_version"] = 4
            peer_dict["config_hold_time"] = self.bgp_server.neighbors[queried_neighbor].hold_timer
            peer_dict["hold_time"] = self.bgp_server.neighbors[queried_neighbor].fsm.hold_timer
            peer_dict["hold_time_left"] = self.bgp_server.neighbors[queried_neighbor].fsm.get_hold_time_left()
            peer_dict["config_keepalive_time"] = self.bgp_server.neighbors[queried_neighbor].keepalive_timer
            peer_dict["keepalive_time"] = self.bgp_server.neighbors[queried_neighbor].fsm.keepalive_timer
            peer_dict["keepalive_time_left"] = self.bgp_server.neighbors[queried_neighbor].fsm.get_keepalive_time_left()
            peer_dict["connect_retry_time_left"] = self.bgp_server.neighbors[queried_neighbor].fsm.get_connect_retry_time_left()
            peer_dict["idle_hold_time_left"] = self.bgp_server.neighbors[queried_neighbor].fsm.get_idle_hold_time_left()
            peer_dict["ttl"] = self.bgp_server.neighbors[queried_neighbor].session.ttl
            peer_dict["max_ttl_hops"] = 255
            peer_dict["in_msg_stats"] = self.bgp_server.neighbors[queried_neighbor].counters.IN_MSG_STATS
            peer_dict["received_messages"] = self.bgp_server.neighbors[queried_neighbor].counters.return_in_msg_stats_summary()
            peer_dict["out_msg_stats"] = self.bgp_server.neighbors[queried_neighbor].counters.OUT_MSG_STATS
            peer_dict["sent_messages"] = self.bgp_server.neighbors[queried_neighbor].counters.return_out_msg_stats_summary()
            peer_dict["last_received"] = str(timedelta(seconds=int(time()) - self.bgp_server.neighbors[queried_neighbor].counters.last_received))
            peer_dict["last_sent"] = str(timedelta(seconds=int(time()) - self.bgp_server.neighbors[queried_neighbor].counters.last_sent))
            peer_dict["last_up_down"] = self.bgp_server.neighbors[queried_neighbor].fsm.get_last_up_down()
            peer_dict["established_transitions"] = self.bgp_server.neighbors[queried_neighbor].fsm.established_transitions
            peer_dict["ls_nlri_received"] = self.bgp_server.neighbors[queried_neighbor].return_received_nlri_count("link-state")
            peer_dict["ls_nlri_sent"] = self.bgp_server.neighbors[queried_neighbor].return_sent_nlri_count("link-state")
            peer_dict["state"] = self.bgp_server.neighbors[queried_neighbor].fsm.state
            peer_dict["admin_down"] = self.bgp_server.neighbors[queried_neighbor].session.admin_down
            peer_dict["pfx_limit_exceeded"] = self.bgp_server.neighbors[queried_neighbor].session.pfx_limit_exceeded
            peer_dict["last_state"] = self.bgp_server.neighbors[queried_neighbor].fsm.last_state
            peer_dict["address_families"] = []
            peer_dict["other_capabilities"] = []
            for cap in self.bgp_server.neighbors[queried_neighbor].fsm.negotiated_capabilities:
                for k, v in BgpCapability.ADDRESS_FAMILIES_SHORT.items():
                    if cap == v:
                        peer_dict["address_families"].append(k)
                for k, v in BgpCapability.OTHER_CAPABILITIES.items():
                    if cap["code"] == v["code"]:
                        peer_dict["other_capabilities"].append(k)
                peer_dict["address_families"].sort()
            #peer_dict["peer_tcp_info"] = None #here can fetch info with getsockopt, for now just use ss or netstat for tshoot
        except KeyError:
            self.bgp_server.logger.exception(f'Bgp show responder: Unable to send BGP neighbor info for {queried_neighbor}')

        return peer_dict
    

    def bgp_neighbors(self, queried_neighbor=None):
        self.bgp_server.logger.debug(f'Bgp show responder: Sending BGP neighbors info')
        peer_list = [] 
        if queried_neighbor:
            if queried_neighbor not in self.bgp_server.neighbors.keys():
                return {"peer_list": peer_list}
            peer_list.append(self.bgp_neighbor_detail(queried_neighbor))
            return {"peer_list": peer_list}
        for queried_neighbor in self.bgp_server.neighbors.keys():
            peer_list.append(self.bgp_neighbor_detail(queried_neighbor))
        return {"peer_list": peer_list}


    def bgp_nlri(self, queried_nlri):
        self.bgp_server.logger.debug(f'Bgp show responder: Sending BGP NLRI info for {queried_nlri}')
        nlri_dict = {}
        # for routes in loc_rib, we will receive a list
        # for adj_rib_in and adj_rib_out we will receive a route, so convert it to a list with one entry
        if isinstance(queried_nlri, list):
            queried_nlri_list = queried_nlri
        else:
            queried_nlri_list = []
            queried_nlri_list.append(queried_nlri)
        nlri_dict[queried_nlri_list[0].route_key] = queried_nlri_list[0].return_route_dict()
        nlri_dict["total_paths"] = len(queried_nlri_list)
        nlri_dict["paths"] = []
        for path_entry in queried_nlri_list:
            path = {}
            path["best"] = path_entry.best
            path["inserted"] = path_entry.inserted
            path["reason_not_best"] = path_entry.reason_not_best
            path["origin"] = path_entry.ORIGINS.get(path_entry.origin, None)
            path["next_hop"] = path_entry.next_hop
            path["local_pref"] = path_entry.local_pref
            path["weight"] = path_entry.weight
            path["originator_id"] = path_entry.originator_id
            path["cluster_list"] = path_entry.cluster_list
            path["as_path"] = {}
            path["as_path"]["as_set"], path["as_path"]["as_sequence"] = path_entry.as_path
            path["last_modified"] = path_entry.last_modified
            path["peer_entry"] = {}
            path["peer_entry"]["remote_router_id"] = path_entry.remote_router_id
            path["peer_entry"]["remote_router_id_override"] = path_entry.remote_router_id_override
            path["peer_entry"]["remote_ip"] = path_entry.remote_ip
            path["peer_entry"]["remote_as"] = path_entry.remote_as
            path["peer_entry"]["link_type"] = path_entry.link_type
            nlri_dict["paths"].append(path)
        return nlri_dict


    def bgp_nlri_detail(self, queried_nlri):
        self.bgp_server.logger.debug(f'Bgp show responder: Sending detailed BGP NLRI info for {queried_nlri}')
        nlri_dict = {}
        # for routes in loc_rib, we will receive a list
        # for adj_rib_in and adj_rib_out we will receive a route, so convert it to a list with one entry
        if isinstance(queried_nlri, list):
            queried_nlri_list = queried_nlri
        else:
            queried_nlri_list = []
            queried_nlri_list.append(queried_nlri)
        nlri_dict[queried_nlri_list[0].route_key] = queried_nlri_list[0].return_route_dict()
        nlri_dict["total_paths"] = len(queried_nlri_list)
        nlri_dict["paths"] = []
        for path_entry in queried_nlri_list:
            path = {}
            path["best"] = path_entry.best
            path["inserted"] = path_entry.inserted
            path["reason_not_best"] = path_entry.reason_not_best
            path["origin"] = path_entry.ORIGINS.get(path_entry.origin, None)
            path["next_hop"] = path_entry.next_hop
            path["local_pref"] = path_entry.local_pref
            path["weight"] = path_entry.weight
            path["originator_id"] = path_entry.originator_id
            path["cluster_list"] = path_entry.cluster_list
            path["as_path"] = {}
            path["as_path"]["as_set"], path["as_path"]["as_sequence"] = path_entry.as_path
            path["last_modified"] = path_entry.last_modified
            path["peer_entry"] = {}
            path["peer_entry"]["remote_router_id"] = path_entry.remote_router_id
            path["peer_entry"]["remote_router_id_override"] = path_entry.remote_router_id_override
            path["peer_entry"]["remote_ip"] = path_entry.remote_ip
            path["peer_entry"]["remote_as"] = path_entry.remote_as
            path["peer_entry"]["link_type"] = path_entry.link_type
            if (path_entry.afi, path_entry.safi) == (BgpCapability.BgpAfi.LS, BgpCapability.BgpSafi.LS):
                path["bgp_ls_attributes"] = path_entry.return_bgp_ls_attributes()
            nlri_dict["paths"].append(path)
        return nlri_dict
    

    def bgp_routing_table(self, queried_rib, queried_nlri=None, detail=False):
        self.bgp_server.logger.debug(f'Bgp show responder: Sending BGP RIB info for {queried_rib}, NLRI {queried_nlri}')
        bgp_routing_table = {}
        bgp_routing_table["router_id"] = self.bgp_server.router_id
        bgp_routing_table["asn"] = self.bgp_server.asn
        bgp_routing_table["bgp_routes"] = []
        if not queried_rib: return bgp_routing_table
        if queried_nlri:
            if queried_nlri not in queried_rib.rib.keys():
                return bgp_routing_table
            queried_nlri_list = queried_rib.rib.get(queried_nlri, None)
            if detail:
                bgp_routing_table["bgp_routes"].append(self.bgp_nlri_detail(queried_nlri_list))
            else:
                bgp_routing_table["bgp_routes"].append(self.bgp_nlri(queried_nlri_list))
            return bgp_routing_table
        
        # copy current list of dict keys and iterate through it
        # this is to avoid RuntimeError when RIB is changing while this command is running
        nlri_to_query = list(queried_rib.rib.keys())

        for queried_nlri in nlri_to_query:
            queried_nlri_list = queried_rib.rib.get(queried_nlri, None)
            if not queried_nlri_list: continue
            if detail:
                bgp_routing_table["bgp_routes"].append(self.bgp_nlri_detail(queried_nlri_list))
            else:
                bgp_routing_table["bgp_routes"].append(self.bgp_nlri(queried_nlri_list))
        
        return bgp_routing_table

    
    def bgp_link_state(self, queried_nlri=None):
        return self.bgp_routing_table(self.bgp_server.ls_loc_rib, queried_nlri, detail=False)


    def bgp_link_state_detail(self, queried_nlri=None):
        return self.bgp_routing_table(self.bgp_server.ls_loc_rib, queried_nlri, detail=True)
    

    def bgp_neighbors_link_state_received_routes(self, queried_neighbor):
        self.bgp_server.logger.debug(f'Bgp show responder: Sending BGP Link-state received routes for neighbor {queried_neighbor}')
        neighbor = self.bgp_server.neighbors.get(queried_neighbor, None)
        if not neighbor:
            adj_rib_in = None
        else:
            adj_rib_in = neighbor.ls_adj_rib_in
        return self.bgp_routing_table(adj_rib_in, queried_nlri=None, detail=False)
    
    
    def bgp_internal(self):
        self.bgp_server.logger.debug(f'Bgp show responder: Sending internal stats')
        bgp_internal = {}
        bgp_internal["running"] = self.bgp_server.running
        bgp_internal["greenthreads_available"] = self.bgp_server.pool.free()
        bgp_internal["config_changes_queued_count"] = self.bgp_server.config_updates.qsize()
        bgp_internal["running_sessions_count"] = len(self.bgp_server.running_sessions)
        bgp_internal["running_sessions"] = self.bgp_server.running_sessions.keys()
        bgp_internal["running_ribs_count"] = len(self.bgp_server.running_ribs)
        bgp_internal["running_ribs"] = self.bgp_server.running_ribs.keys()
        bgp_internal["link_state"] = {}
        bgp_internal["link_state"]["rib_size"] = len(self.bgp_server.ls_loc_rib.rib)
        bgp_internal["link_state"]["update_route_queue_size"] = self.bgp_server.ls_loc_rib.update_route_queue.qsize()
        return bgp_internal
    

    RESPONDERS = {
            "bgp_summary": bgp_summary,
            "bgp_neighbors": bgp_neighbors,
            "bgp_link_state": bgp_link_state,
            "bgp_link_state_detail": bgp_link_state_detail,
            "bgp_neighbors_link_state_received_routes": bgp_neighbors_link_state_received_routes,
            "bgp_internal": bgp_internal,
        }


    def get_response(self, query, command=None):
        self.bgp_server.logger.debug(f'Bgp show responder: Received query {query}, arguments {command}')
        if query not in self.RESPONDERS.keys():
            return
        if command:
            return self.RESPONDERS[query](self, command)
        return self.RESPONDERS[query](self)