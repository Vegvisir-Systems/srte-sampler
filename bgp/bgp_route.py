#!/usr/bin/env python3
from pprint import pprint

from eventlet import GreenPool, listen, connect, greenthread, sleep
from eventlet.queue import Queue
import socket
import struct

from .bgp_defaults import *
from .bgp_message import *


class BgpRoute:
    def __init__(self, afi, safi, inserted=False):
        self.afi = afi
        self.safi = safi
        self.best = False
        self.reason_not_best = None
        self.neighbor = {}
        self.route_key = None
        self.inserted = inserted
        self.last_modified = None
        self.remote_router_id = None
        self.remote_ip = None
        self.remote_as = None
        self.link_type = None
        self.origin = None
        self.as_path = ([], [])
        self.as_path_length = None
        self.next_hop = None
        self.multi_exit_disc = None
        self.local_pref = None
        self.weight = None
        self.originator_id = None
        self.cluster_list = None
        self.inserted = False
        self.install_peer_list = []
        self.remote_router_id_override = None
        
    ORIGINS = {
        0: "igp",
        1: "egp",
        2: "incomplete"
    }

    def set_peer_details(self, remote_router_id, remote_ip, remote_as, link_type):
        self.remote_router_id = remote_router_id
        self.remote_ip = remote_ip
        self.remote_as = remote_as
        self.link_type = link_type

    def set_remote_router_id_override(self, remote_router_id_override):
        self.remote_router_id_override = remote_router_id_override

    def apply_path_attributes(self, origin, as_path, next_hop, multi_exit_disc=0, local_pref=100, weight=0, originator_id=None, cluster_list=[]):
        self.origin = origin
        self.as_path = as_path
        as_set, as_sequence = self.as_path
        self.as_path_length = 0
        if len(as_set) > 0:
            self.as_path_length += 1
        self.as_path_length += len(as_sequence)
        self.next_hop = next_hop
        self.multi_exit_disc = multi_exit_disc
        self.local_pref = local_pref
        self.weight = weight
        self.originator_id = originator_id
        self.cluster_list = cluster_list

    def set_inserted(self):
        self.inserted = True
        self.next_hop = "-"
        self.local_pref = "-"
        self.weight = 0
        self.multi_exit_disc = 0
        self.reason_not_best = "N/A"
        self.link_type = "-"
        self.remote_as = "-"
        self.remote_ip = "-"
        self.remote_router_id = "0.0.0.0"


    def set_install_peer_list(self, install_peer_list):
        self.install_peer_list = install_peer_list



class BgpLuRoute(BgpRoute):
    def __init__(self, afi, label_stack, route_key):
        self.afi = afi
        super().__init__(self.afi, BgpCapability.BgpSafi.LABELED_UNICAST)
        self.label_stack = label_stack
        self.route_key = route_key
        if self.route_key[0] == "[":
            self.prefix = self.route_key.strip("[")
            self.prefix = self.prefix.strip("]")
            self.prefix = self.prefix.split("][")[1]
        else:
            self.prefix = self.route_key
        self.lu_next_hop = None

    def set_lu_next_hop(self, lu_next_hop):
        self.lu_next_hop = lu_next_hop

    def return_route_dict(self):
        route_dict = {}
        if self.afi == BgpCapability.BgpAfi.IPV4:
            route_dict["address_family"] = "ipv4"
        elif self.afi == BgpCapability.BgpAfi.IPV6:
            route_dict["address_family"] = "ipv6"
        route_dict["label_stack"] = self.label_stack
        route_dict["route_key"] = self.route_key
        route_dict["prefix"] = self.prefix
        route_dict["local_bgp_router_id"] = self.remote_router_id
        route_dict["bgp_router_id"] = self.remote_router_id
        if self.remote_router_id_override:
            route_dict["bgp_router_id"] = self.remote_router_id_override
        #route_dict["inserted"] = self.inserted
        return route_dict
    
    #def return_route_dict_detail(self):
    #    return self.return_route_dict()
        

class BgpSrteRoute(BgpRoute):
    def __init__(self, policy_name, route_key, afi, srte_distinguisher, color, endpoint):
        super().__init__(afi, BgpCapability.BgpSafi.SRTE)
        if afi == BgpCapability.BgpAfi.IPV4:
            self.nlri_length = 96
        else:
            self.nlri_length = 192
        self.policy_name = policy_name
        self.route_key = route_key
        self.srte_distinguisher = srte_distinguisher
        self.color = color
        self.endpoint = endpoint
        self.path_preference = None
        self.binding_sid = None
        self.enlp = None
        # EPE policies will always have ENLP none
        self.enlp_override = False
        self.sid_lists = None
        self.route_target = None

    def set_tunnel_encap(self, path_preference, binding_sid, enlp, enlp_override, sid_lists):
        self.path_preference = path_preference
        self.binding_sid = binding_sid
        self.enlp = enlp
        self.enlp_override = enlp_override
        self.sid_lists = sid_lists
        
    def set_route_target(self, route_target):
        self.route_target = route_target


    def return_route_dict(self):
        route_dict = {}
        route_dict["route_key"] = self.route_key
        route_dict["policy_name"] = self.policy_name
        route_dict["srte_distinguisher"] = self.srte_distinguisher
        route_dict["color"] = self.color
        route_dict["endpoint"] = self.endpoint
        route_dict["path_preference"] = self.path_preference
        route_dict["binding_sid"] = self.binding_sid
        route_dict["enlp"] = self.enlp
        route_dict["enlp_override"] = self.enlp_override
        route_dict["sid_lists"] = self.sid_lists
        route_dict["route_target"] = self.route_target
        return route_dict



class BgpLsRoute(BgpRoute):
    def __init__(self, nlri):
        super().__init__(BgpCapability.BgpAfi.LS, BgpCapability.BgpSafi.LS)
        self.type = nlri.type
        self.protocol_id = nlri.protocol_id
        self.identifier = nlri.identifier
        # nlri elements
        self.pseudonode = False
        self.autonomous_system = None
        self.bgp_ls_id = None
        self.igp_router_id = None
        self.bgp_router_id = None
        self.ospf_area_id = None
        self.ospf_dr_address = None
        self.remote_ospf_area_id = None
        self.remote_ospf_dr_address = None
        self.remote_autonomous_system = None
        self.remote_bgp_ls_id = None
        self.remote_igp_router_id = None
        self.remote_bgp_router_id = None
        self.ipv4_interface_address = None
        self.ipv4_neighbor_address = None
        self.ipv6_interface_address = None
        self.ipv6_neighbor_address = None
        self.local_link_id = None
        self.remote_link_id = None
        self.multi_topology_id = None
        self.ospf_route_type = None
        self.prefix = None
        # attributes
        self.lsattr_local_link_id = None
        self.lsattr_remote_link_id = None
        self.lsattr_multi_topology_id = None
        self.msd_type = None
        self.msd = None
        self.node_flags = None
        self.node_name = None
        self.isis_area_id = None
        self.ipv4_local_router_id = None
        self.ipv6_local_router_id = None
        self.ipv4_remote_router_id = None
        self.ipv6_remote_router_id = None
        self.srgb_base = None
        self.srgb_range = None
        self.sr_capability_flags = None
        self.sr_algorithm = None
        self.srlb_base = None
        self.srlb_range = None
        self.admin_group = None
        self.max_link_bandwidth = None
        self.max_reservable_bandwidth = None
        self.unreserved_bandwidth = None
        self.te_default_metric = None
        self.igp_metric = None
        self.srlg = None
        self.adj_sids = None
        self.lan_adj_sids = None
        self.peer_sids = None
        self.igp_flags = None
        self.igp_prefix_metric = None
        self.algorithm = None
        self.prefix_sid = None
        self.prefix_attribute_flags = None
        self.source_router_identifier = None
        self.extended_admin_group = None
        self.protocol_origin = 0
        self.sr_policy_flags = 0
        self.sr_policy_endpoint = None
        self.sr_policy_color = None
        self.bandwidth_rate_bps = 0
        

    # Prefix codes: E link, V node, T IP reacheable route, S SRv6 SID, u/U unknown
    #           I Identifier, N local node, R remote node, L link, P prefix, S SID
    #           L1/L2 ISIS level-1/level-2, O OSPF, D direct, S static/peer-node
    #           a area-ID, l link-ID, t topology-ID, s ISO-ID,
    #           c confed-ID/ASN, b bgp-identifier, r router-ID, s SID
    #           i if-address, n nbr-address, o OSPF Route-type, p IP-prefix
    #           d designated router address

    PROTOCOL_IDS = {
        BgpAttribute.BgpLsNlri.ISIS_LEVEL1: "L1",
        BgpAttribute.BgpLsNlri.ISIS_LEVEL2: "L2",
        BgpAttribute.BgpLsNlri.OSPFV2: "O",
        BgpAttribute.BgpLsNlri.DIRECT: "D",
        BgpAttribute.BgpLsNlri.STATIC: "S",
        BgpAttribute.BgpLsNlri.OSPFV3: "O3",
        BgpAttribute.BgpLsNlri.BGP: "B"
    }    

    def construct_route_key(self):
        if self.protocol_id == BgpAttribute.BgpLsNlri.SR:
            return (f'[SP][SR][I{str(self.identifier)}][N[c{str(self.autonomous_system)}][b{str(self.bgp_ls_id)}][q{str(self.bgp_router_id)}]'
                    f'[{str(self.igp_router_id)}]][C[po{self.protocol_origin}][f{self.sr_policy_flags}][e{self.sr_policy_endpoint}][c{self.sr_policy_color}][as{str(self.autonomous_system)}][oa{str(self.igp_router_id)}][di100]]')
        if self.protocol_id == BgpAttribute.BgpLsNlri.DIRECT:
            #print(f'NLRI from protocol "DIRECT" not supported')
            return
        if self.protocol_id == BgpAttribute.BgpLsNlri.STATIC:
            #print(f'NLRI from protocol "DIRECT" not supported')
            return
        if self.protocol_id == BgpAttribute.BgpLsNlri.OSPFV3:
            #print(f'NLRI from protocol "OSPFV3" not supported')
            return
        if self.type == BgpAttribute.BgpLsNlri.NODE:
            if self.protocol_id == BgpAttribute.BgpLsNlri.ISIS_LEVEL1 or self.protocol_id == BgpAttribute.BgpLsNlri.ISIS_LEVEL2:
                return f'[V][{self.PROTOCOL_IDS.get(self.protocol_id)}][I{str(self.identifier)}][N[c{str(self.autonomous_system)}][b{str(self.bgp_ls_id)}][s{str(self.igp_router_id)}]]'
            elif self.protocol_id == BgpAttribute.BgpLsNlri.OSPFV2:
                if not self.pseudonode:
                    return f'[V][{self.PROTOCOL_IDS.get(self.protocol_id)}][I{str(self.identifier)}][N[c{str(self.autonomous_system)}][b{str(self.bgp_ls_id)}][a{str(self.ospf_area_id)}][r{str(self.igp_router_id)}]]'
                else:
                    return f'[V][{self.PROTOCOL_IDS.get(self.protocol_id)}][I{str(self.identifier)}][N[c{str(self.autonomous_system)}][b{str(self.bgp_ls_id)}][a{str(self.ospf_area_id)}][r{str(self.igp_router_id)}d{str(self.ospf_dr_address)}]]'
            else:
                return
        elif self.type == BgpAttribute.BgpLsNlri.LINK:
            link_string = f'[L'
            if self.ipv4_interface_address:
                link_string += f'[i{str(self.ipv4_interface_address)}]'
            if self.ipv4_neighbor_address:
                link_string += f'[n{str(self.ipv4_neighbor_address)}]'
            if self.ipv6_interface_address:
                link_string += f'[i{str(self.ipv6_interface_address)}]'
            if self.ipv6_neighbor_address:
                link_string += f'[n{str(self.ipv6_neighbor_address)}]'
            if self.local_link_id and self.remote_link_id:
                link_string += f'[l{str(self.local_link_id)}.{str(self.remote_link_id)}]'
            if self.multi_topology_id:
                link_string += f'[t0x{str(self.multi_topology_id).zfill(4)}]'
            link_string += f']'
            if self.protocol_id == BgpAttribute.BgpLsNlri.ISIS_LEVEL1 or self.protocol_id == BgpAttribute.BgpLsNlri.ISIS_LEVEL2:
                return (f'[E][{self.PROTOCOL_IDS.get(self.protocol_id, None)}][I{str(self.identifier)}]'
                        f'[N[c{str(self.autonomous_system)}][b{str(self.bgp_ls_id)}][s{str(self.igp_router_id)}]]'
                        f'[R[c{str(self.remote_autonomous_system)}][b{str(self.remote_bgp_ls_id)}][s{str(self.remote_igp_router_id)}]]'
                        f'{link_string}')
            elif self.protocol_id == BgpAttribute.BgpLsNlri.OSPFV2:
                local_router_id_string = f'[r{str(self.igp_router_id)}]'
                if self.ospf_dr_address:
                    local_router_id_string = local_router_id_string[:-1]
                    local_router_id_string += f'd{str(self.ospf_dr_address)}'
                remote_router_id_string = f'[r{str(self.remote_igp_router_id)}]'
                if self.remote_ospf_dr_address:
                    remote_router_id_string = remote_router_id_string[:-1]
                    remote_router_id_string += f'd{str(self.remote_ospf_dr_address)}'                
                return (f'[E][{self.PROTOCOL_IDS.get(self.protocol_id, None)}][I{str(self.identifier)}]'
                        f'[N[c{str(self.autonomous_system)}][b{str(self.bgp_ls_id)}][a{str(self.ospf_area_id)}]{local_router_id_string}]'
                        f'[R[c{str(self.remote_autonomous_system)}][b{str(self.remote_bgp_ls_id)}][a{str(self.remote_ospf_area_id)}]{remote_router_id_string}]'
                        f'{link_string}')
            elif self.protocol_id == BgpAttribute.BgpLsNlri.BGP:
                return (f'[E][{self.PROTOCOL_IDS.get(self.protocol_id, None)}][I{str(self.identifier)}]'
                        f'[N[c{str(self.autonomous_system)}][b{str(self.bgp_ls_id)}][q{str(self.bgp_router_id)}]]'
                        f'[R[c{str(self.remote_autonomous_system)}][b{str(self.remote_bgp_ls_id)}][q{str(self.remote_bgp_router_id)}]]'
                        f'{link_string}')
        elif self.type == BgpAttribute.BgpLsNlri.IPV4_PREFIX or self.type == BgpAttribute.BgpLsNlri.IPV6_PREFIX:
            prefix_string = f'[P'
            if self.multi_topology_id:
                prefix_string += f'[t0x{str(self.multi_topology_id).zfill(4)}]'
            if self.ospf_route_type:
                prefix_string += f'[o0x{str(self.ospf_route_type).zfill(2)}]'
            prefix_string += f'[p{str(self.prefix)}]'
            prefix_string += f']'
            return f'[T][{self.PROTOCOL_IDS.get(self.protocol_id, None)}][I{str(self.identifier)}][N[c{str(self.autonomous_system)}][b{str(self.bgp_ls_id)}][s{str(self.igp_router_id)}]]{prefix_string}'




    def process_node_nlri(self, nlri):
        for descr in nlri.descriptors:
            if descr.type == BgpAttribute.BgpLsNlri.Descriptor.LOCAL_NODE:
                self.autonomous_system = descr.autonomous_system
                # juniper doesn't use bgp-ls-id by default
                try:
                    self.bgp_ls_id = descr.bgp_ls_id
                except AttributeError:
                    self.bgp_ls_id = 0
                if self.protocol_id == BgpAttribute.BgpLsNlri.BGP:
                    self.bgp_router_id = descr.bgp_router_id
                elif self.protocol_id == BgpAttribute.BgpLsNlri.ISIS_LEVEL1 or self.protocol_id == BgpAttribute.BgpLsNlri.ISIS_LEVEL2:
                    self.igp_router_id = descr.igp_router_id
                    if self.igp_router_id[-2:] != "00":
                        self.pseudonode = True
                elif self.protocol_id == BgpAttribute.BgpLsNlri.OSPFV2:
                    self.igp_router_id = descr.igp_router_id
                    self.ospf_area_id = descr.ospf_area_id
                    try:
                        self.ospf_dr_address = descr.ospf_dr_address
                        self.pseudonode = True
                    except AttributeError:
                        pass
        try:
            self.route_key = self.construct_route_key()
        except:
        #except Exception as e:
            #print(f'Unable to process route {nlri} - exception {e.__class__.__name__, e.args}')
            self.route_key = None

    def process_link_nlri(self, nlri):
        for descr in nlri.descriptors:
            if descr.type == BgpAttribute.BgpLsNlri.Descriptor.LOCAL_NODE:
                self.autonomous_system = descr.autonomous_system
                try:
                    self.bgp_ls_id = descr.bgp_ls_id
                except AttributeError:
                    self.bgp_ls_id = 0
                if self.protocol_id == BgpAttribute.BgpLsNlri.BGP:
                    self.bgp_router_id = descr.bgp_router_id
                elif self.protocol_id == BgpAttribute.BgpLsNlri.ISIS_LEVEL1 or self.protocol_id == BgpAttribute.BgpLsNlri.ISIS_LEVEL2:
                    self.igp_router_id = descr.igp_router_id
                elif self.protocol_id == BgpAttribute.BgpLsNlri.OSPFV2:
                    self.igp_router_id = descr.igp_router_id
                    self.ospf_area_id = descr.ospf_area_id
                    try:
                        self.ospf_dr_address = descr.ospf_dr_address
                    except AttributeError:
                        pass
            if descr.type == BgpAttribute.BgpLsNlri.Descriptor.REMOTE_NODE:
                self.remote_autonomous_system = descr.autonomous_system
                try:
                    self.remote_bgp_ls_id = descr.bgp_ls_id
                except AttributeError:
                    self.remote_bgp_ls_id = 0
                if self.protocol_id == BgpAttribute.BgpLsNlri.BGP:
                    self.remote_bgp_router_id = descr.bgp_router_id
                elif self.protocol_id == BgpAttribute.BgpLsNlri.ISIS_LEVEL1 or self.protocol_id == BgpAttribute.BgpLsNlri.ISIS_LEVEL2:
                    self.remote_igp_router_id = descr.igp_router_id
                elif self.protocol_id == BgpAttribute.BgpLsNlri.OSPFV2:
                    self.remote_igp_router_id = descr.igp_router_id
                    self.remote_ospf_area_id = descr.ospf_area_id
                    try:
                        self.remote_ospf_dr_address = descr.ospf_dr_address
                    except AttributeError:
                        pass
            if descr.type == BgpAttribute.BgpLsNlri.Descriptor.IPV4_INTERFACE_ADDRESS:
                self.ipv4_interface_address = descr.ipv4_interface_address
            if descr.type == BgpAttribute.BgpLsNlri.Descriptor.IPV4_NEIGHBOR_ADDRESS:
                self.ipv4_neighbor_address = descr.ipv4_neighbor_address
            if descr.type == BgpAttribute.BgpLsNlri.Descriptor.IPV6_INTERFACE_ADDRESS:
                self.ipv6_interface_address = descr.ipv6_interface_address
            if descr.type == BgpAttribute.BgpLsNlri.Descriptor.IPV6_NEIGHBOR_ADDRESS:
                self.ipv6_neighbor_address = descr.ipv6_neighbor_address
            if descr.type == BgpAttribute.BgpLsNlri.Descriptor.LINK_LOCAL_REMOTE:
                self.local_link_id = descr.local_link_id
                self.remote_link_id = descr.remote_link_id
            if descr.type == BgpAttribute.BgpLsNlri.Descriptor.MULTI_TOPOLOGY_ID:
                self.multi_topology_id = descr.multi_topology_id[0]
        try:
            self.route_key = self.construct_route_key()
        except:
        #except Exception as e:
            #print(f'Unable to process route {nlri} - exception {e.__class__.__name__, e.args}')
            self.route_key = None

    def process_ip_prefix_nlri(self, nlri):
        for descr in nlri.descriptors:
            if descr.type == BgpAttribute.BgpLsNlri.Descriptor.LOCAL_NODE:
                self.autonomous_system = descr.autonomous_system
                try:
                    self.bgp_ls_id = descr.bgp_ls_id
                except AttributeError:
                    self.bgp_ls_id = 0
                self.igp_router_id = descr.igp_router_id
                if self.protocol_id == BgpAttribute.BgpLsNlri.OSPFV2:
                    self.ospf_area_id = descr.ospf_area_id
            if descr.type == BgpAttribute.BgpLsNlri.Descriptor.IP_REACHABILITY:
                self.prefix = descr.prefix
            if descr.type == BgpAttribute.BgpLsNlri.Descriptor.MULTI_TOPOLOGY_ID:
                self.multi_topology_id = descr.multi_topology_id[0]
            if descr.type == BgpAttribute.BgpLsNlri.Descriptor.OSPF_ROUTE_TYPE:
                self.ospf_route_type = descr.ospf_route_type
        try:
            self.route_key = self.construct_route_key()
        except:
        #except Exception as e:
            #print(f'Unable to process route {nlri} - exception {e.__class__.__name__, e.args}')
            self.route_key = None

        
    def generate_sr_policy_nlri(self, asn, bgp_ls_id, router_id, protocol_origin, sr_policy_flags, sr_policy_endpoint, sr_policy_color):
        self.autonomous_system = asn
        self.bgp_ls_id = bgp_ls_id
        self.bgp_router_id = router_id
        self.igp_router_id = router_id # for SRv6 TBD
        self.protocol_origin = protocol_origin
        self.sr_policy_flags = sr_policy_flags
        self.sr_policy_endpoint = sr_policy_endpoint
        self.sr_policy_color = sr_policy_color
        try:
            self.route_key = self.construct_route_key()
        except:
            self.route_key = None

    def set_sr_policy_bandwidth(self, rate_bps):
        self.bandwidth_rate_bps = rate_bps


    BGP_LS_TYPES = {
        BgpAttribute.BgpLsNlri.NODE: process_node_nlri,
        BgpAttribute.BgpLsNlri.LINK: process_link_nlri,
        BgpAttribute.BgpLsNlri.IPV4_PREFIX: process_ip_prefix_nlri,
        BgpAttribute.BgpLsNlri.IPV6_PREFIX: process_ip_prefix_nlri,
    }

    def process_nlri(self, nlri):
        if self.type not in self.BGP_LS_TYPES.keys():
            #print(f'Unknown BGP LS NLRI Type {self.type}')
            return
        func = self.BGP_LS_TYPES[self.type]
        func(self, nlri)

    def apply_link_local_remote(self, link_state_tlv):
        self.lsattr_local_link_id = link_state_tlv.local_link_id
        self.lsattr_remote_link_id = link_state_tlv.remote_link_id

    def apply_multi_topology_id(self, link_state_tlv):
        self.lsattr_multi_topology_id = link_state_tlv.multi_topology_id

    def apply_msd(self, link_state_tlv):
        self.msd_type = link_state_tlv.msd_type
        self.msd = link_state_tlv.msd

    def apply_node_flag_bits(self, link_state_tlv):
        self.node_flags = link_state_tlv.node_flags

    def apply_node_name(self, link_state_tlv):
        self.node_name = link_state_tlv.node_name

    def apply_isis_area_id(self, link_state_tlv):
        self.isis_area_id = link_state_tlv.isis_area_id

    def apply_ipv4_local_router_id(self, link_state_tlv):
        self.ipv4_local_router_id = link_state_tlv.ipv4_local_router_id

    def apply_ipv6_local_router_id(self, link_state_tlv):
        self.ipv6_local_router_id = link_state_tlv.ipv6_local_router_id

    def apply_ipv4_remote_router_id(self, link_state_tlv):
        self.ipv4_remote_router_id = link_state_tlv.ipv4_remote_router_id

    def apply_ipv6_remote_router_id(self, link_state_tlv):
        self.ipv6_remote_router_id = link_state_tlv.ipv6_remote_router_id

    def apply_sr_capabilities(self, link_state_tlv):
        self.srgb_base = link_state_tlv.srgb_base
        self.srgb_range = link_state_tlv.srgb_range
        self.sr_capability_flags = link_state_tlv.sr_capability_flags

    def apply_sr_algorithm(self, link_state_tlv):
        self.sr_algorithm = link_state_tlv.sr_algorithm

    def apply_sr_local_block(self, link_state_tlv):
        self.srlb_base = link_state_tlv.srlb_base
        self.srlb_range = link_state_tlv.srlb_range

    def apply_admin_group(self, link_state_tlv):
        self.admin_group = link_state_tlv.admin_group

    def apply_max_link_bandwidth(self, link_state_tlv):
        self.max_link_bandwidth = link_state_tlv.max_link_bandwidth

    def apply_max_reservable_bandwidth(self, link_state_tlv):
        self.max_reservable_bandwidth = link_state_tlv.max_reservable_bandwidth

    def apply_unreserved_bandwidth(self, link_state_tlv):
        self.unreserved_bandwidth = link_state_tlv.unreserved_bandwidth

    def apply_te_default_metric(self, link_state_tlv):
        self.te_default_metric = link_state_tlv.te_default_metric

    def apply_igp_metric(self, link_state_tlv):
        self.igp_metric = link_state_tlv.igp_metric

    def apply_srlg(self, link_state_tlv):
        self.srlg = link_state_tlv.srlg

    def apply_adj_sid(self, link_state_tlv):
        if not self.adj_sids:
            self.adj_sids = []
        adj_sid = {}
        adj_sid["weight"] = link_state_tlv.weight
        if self.protocol_id == BgpAttribute.BgpLsNlri.ISIS_LEVEL1 or self.protocol_id == BgpAttribute.BgpLsNlri.ISIS_LEVEL2:
            adj_sid["adj_flags"] = {
                    "af": False,
                    "backup": False,
                    "value": False,
                    "local": False,
                    "set": False,
                    "persistent": False
                }
            if link_state_tlv.flag_bits & 0b10000000:
                adj_sid["adj_flags"]["af"] = True
            if link_state_tlv.flag_bits & 0b01000000:
                adj_sid["adj_flags"]["backup"] = True
            if link_state_tlv.flag_bits & 0b00100000:
                adj_sid["adj_flags"]["value"] = True
            if link_state_tlv.flag_bits & 0b00010000:
                adj_sid["adj_flags"]["local"] = True
            if link_state_tlv.flag_bits & 0b00001000:
                adj_sid["adj_flags"]["set"] = True
            if link_state_tlv.flag_bits & 0b00000100:
                adj_sid["adj_flags"]["persistent"] = True
        elif self.protocol_id == BgpAttribute.BgpLsNlri.OSPFV2:
            adj_sid["adj_flags"] = {
                    "backup": False,
                    "value": False,
                    "local": False,
                    "group": False,
                    "persistent": False
                }
            if link_state_tlv.flag_bits & 0b10000000:
                adj_sid["adj_flags"]["backup"] = True
            if link_state_tlv.flag_bits & 0b01000000:
                adj_sid["adj_flags"]["value"] = True
            if link_state_tlv.flag_bits & 0b00100000:
                adj_sid["adj_flags"]["local"] = True
            if link_state_tlv.flag_bits & 0b00010000:
                adj_sid["adj_flags"]["group"] = True
            if link_state_tlv.flag_bits & 0b00001000:
                adj_sid["adj_flags"]["persistent"] = True
        adj_sid["adj_sid"] = link_state_tlv.adj_sid
        self.adj_sids.append(adj_sid)


    def apply_lan_adj_sid(self, link_state_tlv):
        if not self.lan_adj_sids:
            self.lan_adj_sids = []
        lan_adj_sid = {}
        lan_adj_sid["weight"] = link_state_tlv.weight
        if self.protocol_id == BgpAttribute.BgpLsNlri.ISIS_LEVEL1 or self.protocol_id == BgpAttribute.BgpLsNlri.ISIS_LEVEL2:
            lan_adj_sid["adj_flags"] = {
                    "af": False,
                    "backup": False,
                    "value": False,
                    "local": False,
                    "set": False,
                    "persistent": False
                }
            if link_state_tlv.flag_bits & 0b10000000:
                lan_adj_sid["adj_flags"]["af"] = True
            if link_state_tlv.flag_bits & 0b01000000:
                lan_adj_sid["adj_flags"]["backup"] = True
            if link_state_tlv.flag_bits & 0b00100000:
                lan_adj_sid["adj_flags"]["value"] = True
            if link_state_tlv.flag_bits & 0b00010000:
                lan_adj_sid["adj_flags"]["local"] = True
            if link_state_tlv.flag_bits & 0b00001000:
                lan_adj_sid["adj_flags"]["set"] = True
            if link_state_tlv.flag_bits & 0b00000100:
                lan_adj_sid["adj_flags"]["persistent"] = True
        elif self.protocol_id == BgpAttribute.BgpLsNlri.OSPFV2:
            lan_adj_sid["adj_flags"] = {
                    "backup": False,
                    "value": False,
                    "local": False,
                    "group": False,
                    "persistent": False
                }
            if link_state_tlv.flag_bits & 0b10000000:
                lan_adj_sid["adj_flags"]["backup"] = True
            if link_state_tlv.flag_bits & 0b01000000:
                lan_adj_sid["adj_flags"]["value"] = True
            if link_state_tlv.flag_bits & 0b00100000:
                lan_adj_sid["adj_flags"]["local"] = True
            if link_state_tlv.flag_bits & 0b00010000:
                lan_adj_sid["adj_flags"]["group"] = True
            if link_state_tlv.flag_bits & 0b00001000:
                lan_adj_sid["adj_flags"]["persistent"] = True
        lan_adj_sid["neighbor_router_id"] = link_state_tlv.neighbor_router_id
        lan_adj_sid["lan_adj_sid"] = link_state_tlv.lan_adj_sid
        self.lan_adj_sids.append(lan_adj_sid)

    PEER_SID_TYPES = {
        1101: "peer_node",
        1102: "peer_adj",
        1103: "peer_set"
    }

    def apply_peer_sid(self, link_state_tlv):
        if not self.peer_sids:
            self.peer_sids = []
        peer_sid = {}
        peer_sid["peer_type"] = self.PEER_SID_TYPES[link_state_tlv.type]
        peer_sid["peer_flags"] = {
                "value": False,
                "local": False,
                "backup": False,
                "persistent": False
            }
        if link_state_tlv.flag_bits & 0b10000000:
            peer_sid["peer_flags"]["value"] = True
        if link_state_tlv.flag_bits & 0b01000000:
            peer_sid["peer_flags"]["local"] = True
        if link_state_tlv.flag_bits & 0b00100000:
            peer_sid["peer_flags"]["backup"] = True
        if link_state_tlv.flag_bits & 0b00010000:
            peer_sid["peer_flags"]["persistent"] = True   
        peer_sid["peer_sid"] = link_state_tlv.peer_sid
        self.peer_sids.append(peer_sid)

    def apply_igp_flags(self, link_state_tlv):
        self.igp_flags = link_state_tlv.igp_flags

    def apply_igp_prefix_metric(self, link_state_tlv):
        self.igp_prefix_metric = link_state_tlv.igp_prefix_metric

    def apply_prefix_sid(self, link_state_tlv):
        self.prefix_sid = {}
        self.prefix_sid["algorithm"] = link_state_tlv.algorithm
        self.prefix_sid["prefix_sid"] = link_state_tlv.prefix_sid
        if self.protocol_id == BgpAttribute.BgpLsNlri.ISIS_LEVEL1 or self.protocol_id == BgpAttribute.BgpLsNlri.ISIS_LEVEL2:
            self.prefix_sid["prefix_flags"] = {
                "readvertisement": False,
                "node": False,
                "nophp": False,
                "expnull": False,
                "value": False,
                "local": False
            }
            if link_state_tlv.flag_bits & 0b10000000:
                self.prefix_sid["prefix_flags"]["readvertisement"] = True
            if link_state_tlv.flag_bits & 0b01000000:
                self.prefix_sid["prefix_flags"]["node"] = True
            if link_state_tlv.flag_bits & 0b00100000:
                self.prefix_sid["prefix_flags"]["nophp"] = True
            if link_state_tlv.flag_bits & 0b00010000:
                self.prefix_sid["prefix_flags"]["expnull"] = True
            if link_state_tlv.flag_bits & 0b00001000:
                self.prefix_sid["prefix_flags"]["value"] = True
            if link_state_tlv.flag_bits & 0b00000100:
                self.prefix_sid["prefix_flags"]["local"] = True    
        elif self.protocol_id == BgpAttribute.BgpLsNlri.OSPFV2:
            self.prefix_sid["prefix_flags"] = {
                "nophp": False,
                "mapping_server": False,
                "expnull": False,
                "value": False,
                "local": False,
            }
            if link_state_tlv.flag_bits & 0b01000000:
                self.prefix_sid["prefix_flags"]["nophp"] = True
            if link_state_tlv.flag_bits & 0b00100000:
                self.prefix_sid["prefix_flags"]["mapping_server"] = True
            if link_state_tlv.flag_bits & 0b00010000:
                self.prefix_sid["prefix_flags"]["expnull"] = True
            if link_state_tlv.flag_bits & 0b00001000:
                self.prefix_sid["prefix_flags"]["value"] = True
            if link_state_tlv.flag_bits & 0b00000100:
                self.prefix_sid["prefix_flags"]["local"] = True                

    def apply_prefix_attribute_flags(self, link_state_tlv):
        if self.protocol_id == BgpAttribute.BgpLsNlri.ISIS_LEVEL1 or self.protocol_id == BgpAttribute.BgpLsNlri.ISIS_LEVEL2:
            self.prefix_attribute_flags = {
                "external_prefix": False,
                "readvertisement": False,
                "node": False,
                "elc": False
            }
            if link_state_tlv.flag_bits & 0b10000000:
                self.prefix_attribute_flags["external_prefix"] = True
            if link_state_tlv.flag_bits & 0b01000000:
                self.prefix_attribute_flags["readvertisement"] = True
            if link_state_tlv.flag_bits & 0b00100000:
                self.prefix_attribute_flags["node"] = True
            if link_state_tlv.flag_bits & 0b00010000:
                self.prefix_attribute_flags["elc"] = True
        elif self.protocol_id == BgpAttribute.BgpLsNlri.OSPFV2:
            self.prefix_attribute_flags = {
                "attach": False,
                "node": False
            }
            if link_state_tlv.flag_bits & 0b10000000:
                self.prefix_attribute_flags["attach"] = True
            if link_state_tlv.flag_bits & 0b01000000:
                self.prefix_attribute_flags["node"] = True                        

    def apply_source_router_identifier(self, link_state_tlv):
        self.source_router_identifier = link_state_tlv.source_router_identifier

    def apply_extended_admin_group(self, link_state_tlv):
        self.extended_admin_group = link_state_tlv.extended_admin_group

    BGP_LS_TLVS = {
        BgpAttribute.LinkStateTlv.LINK_LOCAL_REMOTE: apply_link_local_remote,
        BgpAttribute.LinkStateTlv.MULTI_TOPOLOGY_ID: apply_multi_topology_id,
        BgpAttribute.LinkStateTlv.NODE_MSD: apply_msd,
        BgpAttribute.LinkStateTlv.LINK_MSD: apply_msd,
        BgpAttribute.LinkStateTlv.NODE_FLAG_BITS: apply_node_flag_bits,
        BgpAttribute.LinkStateTlv.NODE_NAME: apply_node_name,
        BgpAttribute.LinkStateTlv.ISIS_AREA_ID: apply_isis_area_id,
        BgpAttribute.LinkStateTlv.IPV4_LOCAL_ROUTER_ID: apply_ipv4_local_router_id,
        BgpAttribute.LinkStateTlv.IPV6_LOCAL_ROUTER_ID: apply_ipv6_local_router_id,
        BgpAttribute.LinkStateTlv.IPV4_REMOTE_ROUTER_ID: apply_ipv4_remote_router_id,
        BgpAttribute.LinkStateTlv.IPV6_REMOTE_ROUTER_ID: apply_ipv6_remote_router_id,
        BgpAttribute.LinkStateTlv.SR_CAPABILITIES: apply_sr_capabilities,
        BgpAttribute.LinkStateTlv.SR_ALGORITHM: apply_sr_algorithm,
        BgpAttribute.LinkStateTlv.SR_LOCAL_BLOCK: apply_sr_local_block,
        BgpAttribute.LinkStateTlv.ADMIN_GROUP: apply_admin_group,
        BgpAttribute.LinkStateTlv.MAX_LINK_BANDWIDTH: apply_max_link_bandwidth,
        BgpAttribute.LinkStateTlv.MAX_RESERVABLE_BANDWIDTH: apply_max_reservable_bandwidth,
        BgpAttribute.LinkStateTlv.UNRESERVED_BANDWIDTH: apply_unreserved_bandwidth,
        BgpAttribute.LinkStateTlv.TE_DEFAULT_METRIC: apply_te_default_metric,
        BgpAttribute.LinkStateTlv.IGP_METRIC: apply_igp_metric,
        BgpAttribute.LinkStateTlv.SRLG: apply_srlg,
        BgpAttribute.LinkStateTlv.ADJ_SID: apply_adj_sid,
        BgpAttribute.LinkStateTlv.LAN_ADJ_SID: apply_lan_adj_sid,
        BgpAttribute.LinkStateTlv.PEER_NODE_SID: apply_peer_sid,
        BgpAttribute.LinkStateTlv.PEER_ADJ_SID: apply_peer_sid,
        BgpAttribute.LinkStateTlv.PEER_SET_SID: apply_peer_sid,
        BgpAttribute.LinkStateTlv.IGP_FLAGS: apply_igp_flags,
        BgpAttribute.LinkStateTlv.IGP_PREFIX_METRIC: apply_igp_prefix_metric,
        BgpAttribute.LinkStateTlv.PREFIX_SID: apply_prefix_sid,
        BgpAttribute.LinkStateTlv.PREFIX_ATTRIBUTE_FLAGS: apply_prefix_attribute_flags,
        BgpAttribute.LinkStateTlv.SOURCE_ROUTER_IDENTIFIER: apply_source_router_identifier,
        BgpAttribute.LinkStateTlv.EXTENDED_ADMIN_GROUP: apply_extended_admin_group
    }

    def apply_bgp_ls_attribute(self, link_state_tlvs):
        for link_state_tlv in link_state_tlvs:
            if link_state_tlv.type in self.BGP_LS_TLVS.keys():
                func = self.BGP_LS_TLVS[link_state_tlv.type]
                # this is handled with try/except in BGP FSM anyway, and will log full exception stack
                #try:
                func(self, link_state_tlv)
                #except Exception as e:
                    #print(f"Unable to process Link State TLV {link_state_tlv.type} - exception {e.__class__.__name__, e.args}")


    def return_node_nlri(self):
        node_dict = {}
        node_dict["type"] = "node"
        node_dict["pseudonode"] = self.pseudonode
        node_dict["route_key"] = self.route_key
        if self.identifier: node_dict["identifier"] = self.identifier
        if self.protocol_id: node_dict["protocol_id"] = self.protocol_id
        if self.autonomous_system: node_dict["autonomous_system"] = self.autonomous_system
        if self.bgp_ls_id: node_dict["bgp_ls_id"] = self.bgp_ls_id
        if self.igp_router_id: node_dict["igp_router_id"] = self.igp_router_id
        if self.ospf_area_id: node_dict["ospf_area_id"] = self.ospf_area_id
        if self.ospf_dr_address: node_dict["ospf_dr_address"] = self.ospf_dr_address
        return node_dict
    

    def return_link_nlri(self):
        link_dict = {}
        link_dict["type"] = "link"
        link_dict["route_key"] = self.route_key
        if self.identifier: link_dict["identifier"] = self.identifier
        if self.protocol_id: link_dict["protocol_id"] = self.protocol_id
        if self.autonomous_system: link_dict["autonomous_system"] = self.autonomous_system
        if self.bgp_ls_id: link_dict["bgp_ls_id"] = self.bgp_ls_id
        if self.igp_router_id: link_dict["igp_router_id"] = self.igp_router_id
        if self.bgp_router_id: link_dict["bgp_router_id"] = self.bgp_router_id
        if self.remote_autonomous_system: link_dict["remote_autonomous_system"] = self.remote_autonomous_system
        if self.remote_bgp_ls_id: link_dict["remote_bgp_ls_id"] = self.remote_bgp_ls_id
        if self.remote_igp_router_id: link_dict["remote_igp_router_id"] = self.remote_igp_router_id
        if self.remote_bgp_router_id: link_dict["remote_bgp_router_id"] = self.remote_bgp_router_id
        if self.ipv4_interface_address: link_dict["ipv4_interface_address"] = self.ipv4_interface_address
        if self.ipv4_neighbor_address: link_dict["ipv4_neighbor_address"] = self.ipv4_neighbor_address
        if self.ipv6_interface_address: link_dict["ipv6_interface_address"] = self.ipv6_interface_address
        if self.ipv6_neighbor_address: link_dict["ipv6_neighbor_address"] = self.ipv6_neighbor_address
        if self.local_link_id: link_dict["local_link_id"] = self.local_link_id
        if self.remote_link_id: link_dict["remote_link_id"] = self.remote_link_id
        if self.multi_topology_id: link_dict["multi_topology_id"] = self.multi_topology_id
        if self.ospf_area_id: link_dict["ospf_area_id"] = self.ospf_area_id
        if self.ospf_dr_address: link_dict["ospf_dr_address"] = self.ospf_dr_address
        if self.remote_ospf_area_id: link_dict["remote_ospf_area_id"] = self.remote_ospf_area_id
        if self.remote_ospf_dr_address: link_dict["remote_ospf_dr_address"] = self.remote_ospf_dr_address
        return link_dict
    

    def return_ip_prefix_nlri(self):
        prefix_dict = {}
        if self.type == BgpAttribute.BgpLsNlri.IPV4_PREFIX:
            prefix_dict["type"] = "ipv4_prefix"
        elif self.type == BgpAttribute.BgpLsNlri.IPV6_PREFIX:
            prefix_dict["type"] = "ipv6_prefix"
        prefix_dict["route_key"] = self.route_key
        if self.identifier: prefix_dict["identifier"] = self.identifier
        if self.protocol_id: prefix_dict["protocol_id"] = self.protocol_id
        if self.autonomous_system: prefix_dict["autonomous_system"] = self.autonomous_system
        if self.bgp_ls_id: prefix_dict["bgp_ls_id"] = self.bgp_ls_id
        if self.igp_router_id: prefix_dict["igp_router_id"] = self.igp_router_id
        if self.prefix: prefix_dict["prefix"] = self.prefix
        if self.multi_topology_id: prefix_dict["multi_topology_id"] = self.multi_topology_id
        if self.ospf_route_type: prefix_dict["ospf_route_type"] = self.ospf_route_type
        if self.ospf_area_id: prefix_dict["ospf_area_id"] = self.ospf_area_id
        return prefix_dict


    def return_sr_policy_nlri(self):
        sr_policy_dict = {}
        sr_policy_dict["type"] = "sr_policy"
        sr_policy_dict["route_key"] = self.route_key
        if self.identifier: sr_policy_dict["identifier"] = self.identifier
        if self.protocol_id: sr_policy_dict["protocol_id"] = self.protocol_id
        if self.autonomous_system: sr_policy_dict["autonomous_system"] = self.autonomous_system
        if self.bgp_ls_id: sr_policy_dict["bgp_ls_id"] = self.bgp_ls_id
        if self.bgp_router_id: sr_policy_dict["bgp_router_id"] = self.bgp_router_id
        if self.igp_router_id: sr_policy_dict["igp_router_id"] = self.igp_router_id
        if self.protocol_origin: sr_policy_dict["protocol_origin"] = self.protocol_origin
        if self.sr_policy_flags: sr_policy_dict["sr_policy_flags"] = self.sr_policy_flags
        if self.sr_policy_endpoint: sr_policy_dict["sr_policy_endpoint"] = self.sr_policy_endpoint
        if self.sr_policy_color: sr_policy_dict["sr_policy_color"] = self.sr_policy_color
        return sr_policy_dict


    RETURN_BGP_LS_TYPES = {
        BgpAttribute.BgpLsNlri.NODE: return_node_nlri,
        BgpAttribute.BgpLsNlri.LINK: return_link_nlri,
        BgpAttribute.BgpLsNlri.IPV4_PREFIX: return_ip_prefix_nlri,
        BgpAttribute.BgpLsNlri.IPV6_PREFIX: return_ip_prefix_nlri,
        BgpAttribute.BgpLsNlri.SR_POLICY: return_sr_policy_nlri
    }
    
    def return_route_dict(self):
        if self.type not in self.RETURN_BGP_LS_TYPES.keys():
            return
        func = self.RETURN_BGP_LS_TYPES[self.type]
        return func(self)


    #def return_route_dict_detail(self):
    #    dict_detail = self.return_route_dict()
    #    if not dict_detail: return
    #    dict_detail["ls_attributes"] = self.return_bgp_ls_attributes()
    #    #dict_detail.update(self.return_bgp_ls_attributes())
    #    return dict_detail
        

    def return_bgp_ls_attributes(self):
        attributes_dict = {}
        if self.lsattr_local_link_id: attributes_dict["lsattr_local_link_id"] = self.lsattr_local_link_id
        if self.lsattr_remote_link_id: attributes_dict["lsattr_remote_link_id"] = self.lsattr_remote_link_id
        if self.lsattr_multi_topology_id: attributes_dict["multi_topology_id"] = self.lsattr_multi_topology_id
        if self.msd_type: attributes_dict["msd_type"] = self.msd_type
        if self.msd: attributes_dict["msd"] = self.msd
        if self.node_flags: attributes_dict["node_flags"] = self.node_flags
        if self.node_name: attributes_dict["node_name"] = self.node_name
        if self.isis_area_id: attributes_dict["isis_area_id"] = self.isis_area_id
        if self.ipv4_local_router_id: attributes_dict["ipv4_local_router_id"] = self.ipv4_local_router_id
        if self.ipv6_local_router_id: attributes_dict["ipv6_local_router_id"] = self.ipv6_local_router_id
        if self.ipv4_remote_router_id: attributes_dict["ipv4_remote_router_id"] = self.ipv4_remote_router_id
        if self.ipv6_remote_router_id: attributes_dict["ipv6_remote_router_id"] = self.ipv6_remote_router_id      
        if self.srgb_base: attributes_dict["srgb_base"] = self.srgb_base
        if self.srgb_range: attributes_dict["srgb_range"] = self.srgb_range
        if self.sr_capability_flags: attributes_dict["sr_capability_flags"] = self.sr_capability_flags
        if self.sr_algorithm: attributes_dict["sr_algorithm"] = self.sr_algorithm
        if self.srlb_base: attributes_dict["srlb_base"] = self.srlb_base
        if self.srlb_range: attributes_dict["srlb_range"] = self.srlb_range
        if self.admin_group: attributes_dict["admin_group"] = self.admin_group
        if self.max_link_bandwidth: attributes_dict["max_link_bandwidth"] = self.max_link_bandwidth
        if self.max_reservable_bandwidth: attributes_dict["max_reservable_bandwidth"] = self.max_reservable_bandwidth
        if self.unreserved_bandwidth: attributes_dict["unreserved_bandwidth"] = self.unreserved_bandwidth
        if self.te_default_metric: attributes_dict["te_default_metric"] = self.te_default_metric
        if self.igp_metric: attributes_dict["igp_metric"] = self.igp_metric
        if self.srlg: attributes_dict["srlg"] = self.srlg
        if self.adj_sids: attributes_dict["adj_sids"] = self.adj_sids
        if self.lan_adj_sids: attributes_dict["lan_adj_sids"] = self.lan_adj_sids
        if self.peer_sids: attributes_dict["peer_sids"] = self.peer_sids
        if self.igp_flags: attributes_dict["igp_flags"] = self.igp_flags
        if self.igp_prefix_metric: attributes_dict["igp_prefix_metric"] = self.igp_prefix_metric
        if self.algorithm: attributes_dict["algorithm"] = self.algorithm
        if self.prefix_sid: attributes_dict["prefix_sid"] = self.prefix_sid
        if self.prefix_attribute_flags: attributes_dict["prefix_attribute_flags"] = self.prefix_attribute_flags
        if self.source_router_identifier: attributes_dict["source_router_identifier"] = self.source_router_identifier
        if self.extended_admin_group: attributes_dict["extended_admin_group"] = self.extended_admin_group
        if self.bandwidth_rate_bps: attributes_dict["bandwidth_rate_bps"] = self.bandwidth_rate_bps
        return attributes_dict