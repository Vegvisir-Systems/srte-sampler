#!/usr/bin/env python3
from pprint import pprint
from eventlet import GreenPool, listen, connect, greenthread, sleep
from eventlet.queue import Queue
import socket
import struct
import copy

from .bgp_defaults import *

def ip_to_string(ip_address_bin):
    return socket.inet_ntop(socket.AF_INET, ip_address_bin)

def string_to_ip(ip_address_str):
    return socket.inet_pton(socket.AF_INET, ip_address_str)

def ip6_to_string(ip_address_bin):
    return socket.inet_ntop(socket.AF_INET6, ip_address_bin)

def string_to_ip6(ip_address_str):
    return socket.inet_pton(socket.AF_INET6, ip_address_str)

class BgpMessage:
    MAX_LENGTH = 4096
    HEADER_LENGTH = 19
    MARKER = b"\xff" * 16
    OPEN = 1
    UPDATE = 2
    NOTIFICATION = 3
    KEEPALIVE = 4
    ROUTE_REFRESH = 5

    @staticmethod
    def get_message_type(message_type):
        MESSAGE_TYPES = {
            BgpMessage.OPEN: "Open",
            BgpMessage.UPDATE: "Update",
            BgpMessage.NOTIFICATION: "Notification",
            BgpMessage.KEEPALIVE: "Keepalive",
            BgpMessage.ROUTE_REFRESH: "Route Refresh"
        }
        if message_type in MESSAGE_TYPES.keys():
            return MESSAGE_TYPES[message_type]
        return message_type


class BgpOpen(BgpMessage):
    MESSAGE_TYPE = BgpMessage.OPEN

    def __init__(self, version, asn, hold_timer, router_id, capabilities):
        self.version = version
        self.asn = asn
        self.hold_timer = hold_timer
        self.router_id = router_id
        self.capabilities = capabilities

    @classmethod
    def parse(cls, message_data):
        capabilities = None
        version, asn, hold_timer, router_id_bin, opt_param_length = struct.unpack("!BHH4sB", message_data[:10])
        router_id = ip_to_string(router_id_bin)
        opt_params = message_data[10:10+opt_param_length]
        capabilities = []
        while len(opt_params) > 0:
            param_type, param_length = struct.unpack("!BB", opt_params[:2])           
            if param_type == 2:
                capabilities_bin = opt_params[2:param_length+2]
                parsed_capabilities = BgpOpen.parse_capabilities(capabilities_bin)
                for parsed_cap in parsed_capabilities:
                    capabilities.append(parsed_cap)
            opt_params = opt_params[param_length+2:]

        return cls(version, asn, hold_timer, router_id, capabilities)

    @staticmethod
    def parse_capabilities(capabilities_bin):
        capabilities = []
        while len(capabilities_bin) > 0:
            capability = {}
            capability["code"], capability["len"] = struct.unpack("!BB", capabilities_bin[:2])
            if capability["len"] > 0:
                capability_value_bin = capabilities_bin[2:2+capability["len"]]
                capability["value"] = BgpCapability.parse(capability["len"], capability["code"], capability_value_bin)
            capabilities.append(capability)
            capabilities_bin = capabilities_bin[2+capability["len"]:]
        return capabilities
            
    def generate(self):
        capabilities_bin = b""
        for cap in self.capabilities:
            capabilities_bin += BgpCapability(**cap).generate()
        opt_params = struct.pack("!BB", 2, len(capabilities_bin)) + capabilities_bin
        return struct.pack("!BHH4sB", self.version, self.asn, self.hold_timer, string_to_ip(self.router_id), len(opt_params)) + opt_params

class BgpCapability:
    # https://www.iana.org/assignments/capability-codes/capability-codes.xhtml
    MP_EXTENSIONS = 1
    ROUTE_REFRESH = 2
    ORF = 3
    EXTENDED_NEXT_HOP = 5
    BGP_EXTENDED_MESSAGE = 6
    BGPSEC = 7
    MULTIPLE_LABELS = 8
    BGP_ROLE = 9
    GR = 64
    ASN32 = 65
    DYNAMIC_CAP = 67
    MULTISESSION = 68
    ADD_PATH = 69
    ENHANCED_ROUTE_REFRESH = 70
    LLGR = 71
    RPD = 72
    FQDN = 73
    class BgpAfi:
        # https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
        IPV4 = 1
        IPV6 = 2
        LS = 16388
    class BgpSafi:
        # https://www.iana.org/assignments/safi-namespace/safi-namespace.xml
        UNICAST = 1
        LABELED_UNICAST = 4
        MCAST_VPN = 5
        MDT = 66
        LS = 71
        LS_VPN = 72
        SRTE = 73
        CT = 76
        MCAST_TREE = 78
        LS_SPF = 80


    DEFAULT_CAPABILITIES = [{'code': ROUTE_REFRESH, 'len': 0}]

    ADDRESS_FAMILIES_SHORT = {
        'LS': {'code': MP_EXTENSIONS, 'len': 4, 'value': (BgpAfi.LS, BgpSafi.LS)},
        'IPv4-LU': {'code': MP_EXTENSIONS, 'len': 4, 'value': (BgpAfi.IPV4, BgpSafi.LABELED_UNICAST)},
        'IPv6-LU': {'code': MP_EXTENSIONS, 'len': 4, 'value': (BgpAfi.IPV6, BgpSafi.LABELED_UNICAST)},
        'IPv4-SRTE': {'code': MP_EXTENSIONS, 'len': 4, 'value': (BgpAfi.IPV4, BgpSafi.SRTE)},
        'IPv6-SRTE': {'code': MP_EXTENSIONS, 'len': 4, 'value': (BgpAfi.IPV6, BgpSafi.SRTE)}}

    ADDRESS_FAMILIES = {
        'link-state': {'code': MP_EXTENSIONS, 'len': 4, 'value': (BgpAfi.LS, BgpSafi.LS)},
        'ipv4-labeled-unicast': {'code': MP_EXTENSIONS, 'len': 4, 'value': (BgpAfi.IPV4, BgpSafi.LABELED_UNICAST)},
        'ipv6-labeled-unicast': {'code': MP_EXTENSIONS, 'len': 4, 'value': (BgpAfi.IPV6, BgpSafi.LABELED_UNICAST)},
        'ipv4-srte': {'code': MP_EXTENSIONS, 'len': 4, 'value': (BgpAfi.IPV4, BgpSafi.SRTE)},
        'ipv6-srte': {'code': MP_EXTENSIONS, 'len': 4, 'value': (BgpAfi.IPV6, BgpSafi.SRTE)}}
    
    OTHER_CAPABILITIES = {
        'route-refresh': {'code': ROUTE_REFRESH, 'len': 0},
        'asn32': {'code': ASN32, 'len': 4, 'value': None}
    }

    def __init__(self, code, len, value=None):
        self.code = code
        self.len = len
        self.value = value

    @staticmethod
    def parse(len, code, capability_value_bin):
        if len == 4 and code == BgpCapability.MP_EXTENSIONS:
            return struct.unpack("!HH", capability_value_bin)
        elif len == 4 and code == BgpCapability.ASN32:
            return struct.unpack("!L", capability_value_bin)[0]
 
    def generate(self):
        if self.len == 0:
            return struct.pack("!BB", self.code, self.len)
        elif self.len == 4 and self.code == self.MP_EXTENSIONS:
            return struct.pack("!BBHH", self.code, self.len, self.value[0], self.value[1])
        elif self.len == 4 and self.code == self.ASN32:
            return struct.pack("!BBL", self.code, self.len, self.value)

class BgpUpdate(BgpMessage):
    MESSAGE_TYPE = BgpMessage.UPDATE
    
    def __init__(self, withdrawn_routes_length, withdrawn_routes, path_attribute_length, path_attributes, nlri=None):
        self.withdrawn_routes_length = withdrawn_routes_length
        self.withdrawn_routes = withdrawn_routes
        self.path_attribute_length = path_attribute_length
        self.path_attributes = path_attributes
        self.nlri = nlri

    @classmethod
    def parse(cls, message_data):
        withdrawn_routes_length = struct.unpack("!H", message_data[:2])[0]
        withdrawn_routes = message_data[2:2+withdrawn_routes_length]
        message_data = message_data[2+withdrawn_routes_length:]
        path_attribute_length = struct.unpack("!H", message_data[:2])[0]
        path_attributes_bin = message_data[2:2+path_attribute_length]
        nlri = message_data[2+path_attribute_length:]
        path_attributes = BgpUpdate.parse_attributes(path_attributes_bin)
        return cls(withdrawn_routes_length, withdrawn_routes, path_attribute_length, path_attributes, nlri)

    @staticmethod
    def parse_attributes(path_attributes_bin):
        path_attributes = []
        while len(path_attributes_bin) > 0:
            attr = {
                "optional": False,
                "transitive": False,
                "partial": False,
                "extended_length": False
            }
            attr_flags, attr["type_code"] = struct.unpack("!BB", path_attributes_bin[:2])
            if attr_flags & 0b10000000:
                attr["optional"] = True
            if attr_flags & 0b01000000:
                attr["transitive"] = True
            if attr_flags & 0b00100000:
                attr["partial"] = True
            if attr_flags & 0b00010000:
                attr["extended_length"] = True

            if attr["extended_length"]:
                attr["length"] = struct.unpack("!H", path_attributes_bin[2:4])[0]
                path_attributes_bin = path_attributes_bin[4:]
            else:
                attr["length"] = struct.unpack("!B", path_attributes_bin[2:3])[0]
                path_attributes_bin = path_attributes_bin[3:]
            
            attr_bin_data = path_attributes_bin[:attr["length"]]
            path_attributes_bin = path_attributes_bin[attr["length"]:]
            attribute = BgpAttribute(**attr)
            attribute.parse_bin_data(attr_bin_data)
            path_attributes.append(attribute)

        return path_attributes
    
    def generate(self):
        message = struct.pack("!H", 0)
        path_attributes_bin = b""
        for path_attribute in self.path_attributes:
            path_attribute_bin = path_attribute.generate()
            if len(path_attribute_bin) > 255:
                path_attribute.extended_length = True
            attr_flags = 0b00000000
            if path_attribute.optional:
                attr_flags += 0b10000000
            if path_attribute.transitive:
                attr_flags += 0b01000000
            if path_attribute.partial:
                attr_flags += 0b00100000
            if path_attribute.extended_length:
                attr_flags += 0b00010000
            path_attributes_bin += struct.pack("!BB", attr_flags, path_attribute.type_code)
            if path_attribute.extended_length:
                path_attributes_bin += struct.pack("!H", len(path_attribute_bin))
            else:
                path_attributes_bin += struct.pack("!B", len(path_attribute_bin))
            path_attributes_bin += path_attribute_bin
        message += struct.pack("!H", len(path_attributes_bin))
        message += path_attributes_bin
        return message
            





class BgpAttribute:
    ORIGIN = 1
    AS_PATH = 2
    NEXT_HOP = 3
    MULTI_EXIT_DISC = 4
    LOCAL_PREF = 5
    ATOMIC_AGGREGATE = 6
    AGGREGATOR = 7
    COMMUNITY = 8
    ORIGINATOR_ID = 9
    CLUSTER_LIST = 10
    MP_REACH_NLRI = 14
    MP_UNREACH_NLRI = 15
    EXT_COMMUNITIES = 16
    AS4_PATH = 17
    AS4_AGGREGATOR = 18
    PMSI_TUNNEL = 22
    TUNNEL_ENCAP = 23
    TRAFFIC_ENG = 24
    IPV6_SPECIFIC_EXTCOMMUNITY = 25
    AIGP = 26
    PE_DISTINGUISHER_LABELS = 27
    BGP_LS = 29
    LARGE_COMMUNITY = 32
    BGP_PREFIX_SID = 40
    ATTR_SET = 128

        

    def __init__(self, optional, transitive, partial, extended_length, type_code, length):
        self.optional = optional
        self.transitive = transitive
        self.partial = partial
        self.extended_length = extended_length
        self.type_code = type_code
        self.length = length

    def parse_origin(self, attr_bin_data):
        self.origin = struct.unpack("!B", attr_bin_data)[0]
    
    def parse_as_path(self, attr_bin_data):
        as_set = []
        as_sequence = []
        while len(attr_bin_data) > 0:
            segment_type, segment_length = struct.unpack("!BB", attr_bin_data[:2])
            attr_bin_data = attr_bin_data[2:]
            # this might not parse BGP attributes properly if neighbor doesn't support 4 byte ASN
            # and sends an AS_PATH with both AS_SEQ and AS_SET
            if len(attr_bin_data) / segment_length > 2:
                # assuming 4 byte ASNs
                if segment_type == 1: # AS_SET
                    for i in range(segment_length):
                        as_set.append(struct.unpack("!L", attr_bin_data[:4])[0])
                        attr_bin_data = attr_bin_data[4:]
                elif segment_type == 2: # AS_SEQUENCE
                    for i in range(segment_length):
                        as_sequence.append(struct.unpack("!L", attr_bin_data[:4])[0])
                        attr_bin_data = attr_bin_data[4:]
            else:
                if segment_type == 1: # AS_SET
                    for i in range(segment_length):
                        as_set.append(struct.unpack("!H", attr_bin_data[:2])[0])
                        attr_bin_data = attr_bin_data[2:]
                elif segment_type == 2: # AS_SEQUENCE
                    for i in range(segment_length):
                        as_sequence.append(struct.unpack("!H", attr_bin_data[:2])[0])
                        attr_bin_data = attr_bin_data[2:]
        self.as_path = (as_set, as_sequence)

    def parse_multi_exit_disc(self, attr_bin_data):
        self.multi_exit_disc = struct.unpack("!L", attr_bin_data)[0]

    def parse_local_pref(self, attr_bin_data):
        self.local_pref = struct.unpack("!L", attr_bin_data)[0]

    def parse_originator_id(self, attr_bin_data):
        self.originator_id = ip_to_string(struct.unpack("!4s", attr_bin_data)[0])

    def parse_cluster_list(self, attr_bin_data):
        self.cluster_list = []
        while len(attr_bin_data) > 0:
            cluster_id = ip_to_string(struct.unpack("!4s", attr_bin_data[:4])[0])
            attr_bin_data = attr_bin_data[4:]
            self.cluster_list.append(cluster_id)

    def parse_large_community(self, attr_bin_data):
        self.asn, self.local_data1, self.local_data2 = struct.unpack("!LLL", attr_bin_data)

    def parse_mp_reach_nlri(self, attr_bin_data):
        self.afi, self.safi, next_hop_length = struct.unpack("!HBB", attr_bin_data[:4])
        attr_bin_data = attr_bin_data[4:]
        if next_hop_length == 4:
            next_hop_bin = struct.unpack("!4s", attr_bin_data[:4])[0]
            self.next_hop = ip_to_string(next_hop_bin)
        elif next_hop_length == 16:
            next_hop_bin = struct.unpack("!16s", attr_bin_data[:16])[0]
            self.next_hop = ip6_to_string(next_hop_bin)
        # ignore link local IPv6
        elif next_hop_length == 32:
            next_hop_bin = struct.unpack("!16s", attr_bin_data[:16])[0]
            self.next_hop = ip6_to_string(next_hop_bin)            
        attr_bin_data = attr_bin_data[next_hop_length:]
        attr_bin_data = attr_bin_data[1:] # 1 byte reserved
        if self.afi == BgpCapability.BgpAfi.LS and self.safi == BgpCapability.BgpSafi.LS:
            self.parse_bgp_ls_nlri(attr_bin_data)
        elif self.safi == BgpCapability.BgpSafi.LABELED_UNICAST:
            self.parse_bgp_lu_nlri(self.afi, attr_bin_data)
        else:
            pass
            #print(f'Received MP_REACH_NLRI with unsupported AFI {self.afi}, SAFI {self.safi}, bytes {attr_bin_data.hex(" ", 1)}')

    def parse_mp_unreach_nlri(self, attr_bin_data):
        self.afi, self.safi = struct.unpack("!HB", attr_bin_data[:3])
        attr_bin_data = attr_bin_data[3:]
        if self.afi == BgpCapability.BgpAfi.LS and self.safi == BgpCapability.BgpSafi.LS:
            self.parse_bgp_ls_nlri(attr_bin_data)
        elif self.safi == BgpCapability.BgpSafi.LABELED_UNICAST:
            self.parse_bgp_lu_nlri(self.afi, attr_bin_data)
        else:
            pass
            #print(f'Received MP_UNREACH_NLRI with unsupported AFI {self.afi}, SAFI {self.safi}, bytes {attr_bin_data.hex(" ", 1)}')

    def parse_bgp_ls_attribute(self, attr_bin_data):
        self.link_state_tlvs = []
        while len(attr_bin_data) > 0:
            tlv = {}
            tlv["type"], tlv["length"] = struct.unpack("!HH", attr_bin_data[:4])
            attr_bin_data = attr_bin_data[4:]
            tlv_bin_data = attr_bin_data[:tlv["length"]]
            attr_bin_data = attr_bin_data[tlv["length"]:]
            link_state_tlv = self.LinkStateTlv(**tlv)
            link_state_tlv.parse_bin_data(tlv_bin_data)
            self.link_state_tlvs.append(link_state_tlv)

    class LinkStateTlv:
        # https://datatracker.ietf.org/doc/html/rfc7752
        # https://datatracker.ietf.org/doc/html/rfc9085
        # https://datatracker.ietf.org/doc/html/rfc9086
        # https://datatracker.ietf.org/doc/rfc8814
        # https://datatracker.ietf.org/doc/html/rfc8491
        # 
        LINK_LOCAL_REMOTE = 258         # done
        MULTI_TOPOLOGY_ID = 263         # done
        NODE_MSD = 266                  # done
        LINK_MSD = 267                  # done
        NODE_FLAG_BITS = 1024           # done
        OPAQUE_NODE_ATTRIBUTE = 1025
        NODE_NAME = 1026                # done
        ISIS_AREA_ID = 1027             # done
        IPV4_LOCAL_ROUTER_ID = 1028     # done
        IPV6_LOCAL_ROUTER_ID = 1029     # done
        IPV4_REMOTE_ROUTER_ID = 1030    # done
        IPV6_REMOTE_ROUTER_ID = 1031    # done
        SR_CAPABILITIES = 1034          # done
        SR_ALGORITHM = 1035             # done
        SR_LOCAL_BLOCK = 1036           # done
        SRMS_PREFERENCE = 1037
        ADMIN_GROUP = 1088              # done
        MAX_LINK_BANDWIDTH = 1089       # done
        MAX_RESERVABLE_BANDWIDTH = 1090 # done
        UNRESERVED_BANDWIDTH = 1091     # done
        TE_DEFAULT_METRIC = 1092        # done
        LINK_PROTECTION_TYPE = 1093
        MPLS_PROTOCOL_MASK = 1094
        IGP_METRIC = 1095               # done
        SRLG = 1096                     # done
        OPAQUE_LINK_ATTRIBUTE = 1097
        LINK_NAME = 1098
        ADJ_SID = 1099                  # done
        LAN_ADJ_SID = 1100              # done
        PEER_NODE_SID = 1101            # done
        PEER_ADJ_SID = 1102             # done
        PEER_SET_SID = 1103             # done
        APP_SPECIFIC_LINK_ATTRIBUTES = 1122
        IGP_FLAGS = 1152                # done
        IGP_ROUTE_TAG = 1153
        IGP_EXTENDED_ROUTE_TAG = 1154
        IGP_PREFIX_METRIC = 1155        # done
        OSPF_FORWARDING_ADDRESS = 1156
        OPAQUE_PREFIX_ATTRIBUTE = 1157 
        PREFIX_SID = 1158               # done
        RANGE = 1159
        SID_LABEL = 1161                # done
        PREFIX_ATTRIBUTE_FLAGS = 1170   # done
        SOURCE_ROUTER_IDENTIFIER = 1171 # done
        L2_BUNDLE_MEMBER_ATTRIBUTES = 1172
        EXTENDED_ADMIN_GROUP = 1173     # done
        SOURCE_OSPF_ROUTER_ID = 1174
        # SR policy TLV
        # https://datatracker.ietf.org/doc/html/rfc9857#name-bgp-ls-tlvs
        SR_BINDING_SID = 1201
        SR_CANDIDATE_PATH_STATE = 1202
        SR_CANDIDATE_PATH_NAME = 1203
        SR_CANDIDATE_PATH_CONSTRAINTS = 1204
        SR_SEGMENT_LIST = 1205
        SR_SEGMENT = 1206
        SR_SEGMENT_LIST_METRIC = 1207
        SR_AFFINITY_CONSTRAINT = 1208
        SR_SRLG_CONSTRAINT = 1209
        SR_BANDWIDTH_CONSTRAINT = 1210
        SR_DISJOINT_GROUP_CONSTRAINT = 1211
        SRV6_BINDING_SID = 1212
        SR_POLICY_NAME = 1213
        SR_BIDIR_GROUP_CONSTRAINT = 1214
        SR_METRIC_CONSTRAINT = 1215
        SR_SEGMENT_LIST_BANDWIDTH = 1216
        SR_SEGMENT_LIST_IDENTIFIER = 1217



        def __init__(self, type, length):
            self.type = type
            self.length = length

        def parse_link_local_remote(self, tlv_bin_data):
            self.local_link_id, self.remote_link_id = struct.unpack("!LL", tlv_bin_data)

        def parse_multi_topology_id(self, tlv_bin_data):
            self.multi_topology_id = []
            while len(tlv_bin_data) > 0:
                mt_id = struct.unpack("!H", tlv_bin_data[:2])[0]
                self.multi_topology_id.append(mt_id)
                tlv_bin_data = tlv_bin_data[2:]     

        def parse_node_msd(self, tlv_bin_data):
            self.msd_type, self.msd = struct.unpack("!BB", tlv_bin_data[:2])

        def parse_link_msd(self, tlv_bin_data):
            self.msd_type, self.msd = struct.unpack("!BB", tlv_bin_data[:2])

        def parse_node_flag_bits(self, tlv_bin_data):
            flag_bits = struct.unpack("!B", tlv_bin_data)[0]
            self.node_flags = {
                "overload": False,
                "attached": False,
                "external": False,
                "abr": False,
                "router": False,
                "v6": False
            }
            if flag_bits & 0b10000000:
                self.node_flags["overload"] = True
            if flag_bits & 0b01000000:
                self.node_flags["attached"] = True
            if flag_bits & 0b00100000:
                self.node_flags["external"] = True
            if flag_bits & 0b00010000:
                self.node_flags["abr"] = True
            if flag_bits & 0b00001000:
                self.node_flags["router"] = True
            if flag_bits & 0b00000100:
                self.node_flags["v6"] = True

        def parse_node_name(self, tlv_bin_data):
            self.node_name = tlv_bin_data.decode("utf-8")

        def parse_isis_area_id(self, tlv_bin_data):
            self.isis_area_id = tlv_bin_data.hex('.', 2)

        def parse_ipv4_local_router_id(self, tlv_bin_data):
            ipv4_local_router_id_bin = struct.unpack("!4s", tlv_bin_data)[0]
            self.ipv4_local_router_id = ip_to_string(ipv4_local_router_id_bin)
                
        def parse_ipv6_local_router_id(self, tlv_bin_data):
            ipv6_local_router_id_bin = struct.unpack("!16s", tlv_bin_data)[0]
            self.ipv6_local_router_id = ip6_to_string(ipv6_local_router_id_bin)

        def parse_ipv4_remote_router_id(self, tlv_bin_data):
            ipv4_remote_router_id_bin = struct.unpack("!4s", tlv_bin_data)[0]
            self.ipv4_remote_router_id = ip_to_string(ipv4_remote_router_id_bin)
                
        def parse_ipv6_remote_router_id(self, tlv_bin_data):
            ipv6_remote_router_id_bin = struct.unpack("!16s", tlv_bin_data)[0]
            self.ipv6_remote_router_id = ip6_to_string(ipv6_remote_router_id_bin)

        def parse_sr_capabilities(self, tlv_bin_data):
            flag_bits, _, range_size = struct.unpack("!BB3s", tlv_bin_data[:5])
            self.sr_capability_flags = {
                "mpls_ipv4": False,
                "mpls_ipv6": False,
                "srv6": False
            }
            if flag_bits & 0b10000000:
                self.sr_capability_flags["mpls_ipv4"] = True
            if flag_bits & 0b01000000:
                self.sr_capability_flags["mpls_ipv6"] = True
            if flag_bits & 0b00100000:
                self.sr_capability_flags["srv6"] = True
            self.srgb_range = int(range_size.hex(),16)
            if int(tlv_bin_data[5:7].hex(),16) == self.SID_LABEL:
                self.srgb_base = self.parse_sid_label(tlv_bin_data[7:])

        def parse_sr_algorithm(self, tlv_bin_data):
            self.sr_algorithm = []
            for i in range (self.length):
                self.sr_algorithm.append(tlv_bin_data[i])

        def parse_sr_local_block(self, tlv_bin_data):
            self.srlb_range = int(tlv_bin_data[2:5].hex(),16)
            if int(tlv_bin_data[5:7].hex(),16) == self.SID_LABEL:
                self.srlb_base = self.parse_sid_label(tlv_bin_data[7:])

        def parse_admin_group(self, tlv_bin_data):
            self.admin_group = hex(struct.unpack("!L", tlv_bin_data)[0])

        def parse_max_link_bandwidth(self, tlv_bin_data):
            # if ever need to convert back, try the following:
            # binary = struct.pack('>f', decimal)
            # binary_string = ''.join(f'{byte:08b}' for byte in binary)

            bandwidth_ieee754 = struct.unpack("!L", tlv_bin_data)[0]
            bandwidth_bin_string = str(bin(bandwidth_ieee754))[2:]
            while len(bandwidth_bin_string) < 32:
                bandwidth_bin_string = '0' + bandwidth_bin_string
            binary_chunks = [bandwidth_bin_string[i:i+8] for i in range(0, len(bandwidth_bin_string), 8)]
            binary_data = bytes(int(chunk, 2) for chunk in binary_chunks)
            bandwith_bytes = struct.unpack('>f', binary_data)[0]

            # workaround for imprecise display of bw >25 gbps
            # for bw over 10 gbps, round over to the next 1 gbps
            # works fine for links up to 4 tbps
            max_link_bandwidth = int(bandwith_bytes * 8)
            if max_link_bandwidth > 1000000000:
                bw_units = max_link_bandwidth // 1000000000
                if max_link_bandwidth % 1000000000 > 0:
                    bw_units += 1
                max_link_bandwidth = bw_units * 1000000000

            self.max_link_bandwidth = max_link_bandwidth

        def parse_max_reservable_bandwidth(self, tlv_bin_data):
            bandwidth_ieee754 = struct.unpack("!L", tlv_bin_data)[0]
            bandwidth_bin_string = str(bin(bandwidth_ieee754))[2:]
            while len(bandwidth_bin_string) < 32:
                bandwidth_bin_string = '0' + bandwidth_bin_string
            binary_chunks = [bandwidth_bin_string[i:i+8] for i in range(0, len(bandwidth_bin_string), 8)]
            binary_data = bytes(int(chunk, 2) for chunk in binary_chunks)
            bandwith_bytes = struct.unpack('>f', binary_data)[0]

            # workaround for imprecise display of bw >25 gbps
            # for bw over 10 gbps, round over to the next 1 gbps
            # works fine for links up to 4 tbps
            max_reservable_bandwidth = int(bandwith_bytes * 8)
            if max_reservable_bandwidth > 1000000000:
                bw_units = max_reservable_bandwidth // 1000000000
                if max_reservable_bandwidth % 1000000000 > 0:
                    bw_units += 1
                max_reservable_bandwidth = bw_units * 1000000000

            self.max_reservable_bandwidth = max_reservable_bandwidth

        def parse_unreserved_bandwidth(self, tlv_bin_data):
            priorities = []
            while len(tlv_bin_data) > 0:
                bandwidth_ieee754 = struct.unpack("!L", tlv_bin_data[:4])[0]
                bandwidth_bin_string = str(bin(bandwidth_ieee754))[2:]
                while len(bandwidth_bin_string) < 32:
                    bandwidth_bin_string = '0' + bandwidth_bin_string
                binary_chunks = [bandwidth_bin_string[i:i+8] for i in range(0, len(bandwidth_bin_string), 8)]
                binary_data = bytes(int(chunk, 2) for chunk in binary_chunks)
                bandwith_bytes = struct.unpack('>f', binary_data)[0]
                # workaround for imprecise display of bw >25 gbps
                # for bw over 10 gbps, round over to the next 1 gbps
                # works fine for links up to 4 tbps
                unrsv_bandwidth = int(bandwith_bytes * 8)
                if unrsv_bandwidth > 1000000000:
                    bw_units = unrsv_bandwidth // 1000000000
                    if unrsv_bandwidth % 1000000000 > 0:
                        bw_units += 1
                    unrsv_bandwidth = bw_units * 1000000000
                priorities.append(unrsv_bandwidth)
                tlv_bin_data = tlv_bin_data[4:]
            if len(priorities) != 8: return
            self.unreserved_bandwidth = priorities
                             
        def parse_te_default_metric(self, tlv_bin_data):
            self.te_default_metric = int(tlv_bin_data.hex(),16)

        def parse_igp_metric(self, tlv_bin_data):
            self.igp_metric = int(tlv_bin_data.hex(),16)

        def parse_srlg(self, tlv_bin_data):
            self.srlg = []
            while len(tlv_bin_data) > 0:
                srlg = struct.unpack("!L", tlv_bin_data[:4])[0]
                self.srlg.append(srlg)
                tlv_bin_data = tlv_bin_data[4:]
            
        def parse_adj_sid(self, tlv_bin_data):
            self.flag_bits, self.weight, _ = struct.unpack("!BBH", tlv_bin_data[:4])
            self.adj_sid = int(tlv_bin_data[4:].hex(),16)

        def parse_lan_adj_sid(self, tlv_bin_data):
            self.flag_bits, self.weight, _ = struct.unpack("!BBH", tlv_bin_data[:4])
            if self.length > 12:
                # ISIS
                self.neighbor_router_id = struct.unpack("!6s", tlv_bin_data[4:10])[0].hex('.', 2)
                self.lan_adj_sid = int(tlv_bin_data[10:].hex(),16)
            else:
                # OSPF
                neighbor_router_id_bin = struct.unpack("!4s", tlv_bin_data[4:8])[0]
                self.neighbor_router_id = ip_to_string(neighbor_router_id_bin)
                self.lan_adj_sid = int(tlv_bin_data[8:].hex(),16)                

        def parse_peer_sid(self, tlv_bin_data):
            self.flag_bits, self.weight, _ = struct.unpack("!BBH", tlv_bin_data[:4])
            self.peer_sid = int(tlv_bin_data[4:].hex(),16)

        def parse_igp_flags(self, tlv_bin_data):
            flag_bits = struct.unpack("!B", tlv_bin_data)[0]
            self.igp_flags = {
                "isis_down": False,
                "ospf_no_unicast": False,
                "ospf_local_address": False,
                "ospf_propagate_nssa": False
            }
            if flag_bits & 0b10000000:
                self.igp_flags["isis_down"] = True
            if flag_bits & 0b01000000:
                self.igp_flags["ospf_no_unicast"] = True
            if flag_bits & 0b00100000:
                self.igp_flags["ospf_local_address"] = True
            if flag_bits & 0b00010000:
                self.igp_flags["ospf_propagate_nssa"] = True

        def parse_igp_prefix_metric(self, tlv_bin_data):
            self.igp_prefix_metric = int(tlv_bin_data.hex(),16)

        def parse_prefix_sid(self, tlv_bin_data):
            self.flag_bits, self.algorithm, _ = struct.unpack("!BBH", tlv_bin_data[:4])         
            self.prefix_sid = int(tlv_bin_data[4:].hex(),16)

        @staticmethod
        def parse_sid_label(tlv_bin_data):
            tlv_length = int(tlv_bin_data[:2].hex(),16)
            if tlv_length == 3:
                return int(tlv_bin_data[2:5].hex(),16)
            
        def parse_prefix_attribute_flags(self, tlv_bin_data):
            # https://datatracker.ietf.org/doc/html/rfc7794#section-2.1
            # https://datatracker.ietf.org/doc/html/draft-ietf-isis-mpls-elc-13
            # https://datatracker.ietf.org/doc/html/rfc7684#section-2.1
            self.flag_bits = struct.unpack("!B", tlv_bin_data[:1])[0]


        def parse_source_router_identifier(self, tlv_bin_data):
            if self.length == 4:
                source_router_identifier_bin = struct.unpack("!4s", tlv_bin_data)[0]
                self.source_router_identifier = ip_to_string(source_router_identifier_bin)
            elif self.length == 16:
                source_router_identifier_bin = struct.unpack("!16s", tlv_bin_data)[0]
                self.source_router_identifier = ip6_to_string(source_router_identifier_bin)                

        def parse_extended_admin_group(self, tlv_bin_data):
            priorities = []
            while len(tlv_bin_data) > 0:
                extended_admin_group = hex(struct.unpack("!L", tlv_bin_data[:4])[0])
                priorities.append(extended_admin_group)
                tlv_bin_data = tlv_bin_data[4:]
            #if len(priorities) != 8: return
            self.extended_admin_group = priorities

        parsers = {
            NODE_MSD: parse_node_msd,
            LINK_MSD: parse_link_msd,
            NODE_FLAG_BITS: parse_node_flag_bits,
            NODE_NAME: parse_node_name,
            ISIS_AREA_ID: parse_isis_area_id,
            IPV4_LOCAL_ROUTER_ID: parse_ipv4_local_router_id,
            IPV6_LOCAL_ROUTER_ID: parse_ipv6_local_router_id,
            IPV4_REMOTE_ROUTER_ID: parse_ipv4_remote_router_id,
            IPV6_REMOTE_ROUTER_ID: parse_ipv6_remote_router_id,
            LINK_LOCAL_REMOTE: parse_link_local_remote,
            MULTI_TOPOLOGY_ID: parse_multi_topology_id,
            SR_CAPABILITIES: parse_sr_capabilities,
            SR_ALGORITHM: parse_sr_algorithm,
            SR_LOCAL_BLOCK: parse_sr_local_block,
            ADMIN_GROUP: parse_admin_group,
            MAX_LINK_BANDWIDTH: parse_max_link_bandwidth,
            MAX_RESERVABLE_BANDWIDTH: parse_max_reservable_bandwidth,
            UNRESERVED_BANDWIDTH: parse_unreserved_bandwidth,
            TE_DEFAULT_METRIC: parse_te_default_metric,
            IGP_METRIC: parse_igp_metric,
            SRLG: parse_srlg,
            ADJ_SID: parse_adj_sid,
            LAN_ADJ_SID: parse_lan_adj_sid,
            PEER_NODE_SID: parse_peer_sid,
            PEER_ADJ_SID: parse_peer_sid,
            PEER_SET_SID: parse_peer_sid,
            IGP_FLAGS: parse_igp_flags,
            IGP_PREFIX_METRIC: parse_igp_prefix_metric,
            PREFIX_SID: parse_prefix_sid,
            PREFIX_ATTRIBUTE_FLAGS: parse_prefix_attribute_flags,
            SOURCE_ROUTER_IDENTIFIER: parse_source_router_identifier,
            EXTENDED_ADMIN_GROUP: parse_extended_admin_group
        }

        def parse_bin_data(self, tlv_bin_data):
            if self.type in self.parsers.keys():
                func = self.parsers[self.type]
                func(self, tlv_bin_data)
            

    def parse_bgp_ls_nlri(self, attr_bin_data):
        self.bgp_ls_nlris = []
        while len(attr_bin_data) > 0:
            nlri = {}
            nlri["type"], nlri["length"] = struct.unpack("!HH", attr_bin_data[:4])
            attr_bin_data = attr_bin_data[4:]
            nlri_bin_data = attr_bin_data[:nlri["length"]]
            attr_bin_data = attr_bin_data[nlri["length"]:]
            bgp_ls_nlri = self.BgpLsNlri(**nlri)
            bgp_ls_nlri.parse_bin_data(nlri_bin_data)
            self.bgp_ls_nlris.append(bgp_ls_nlri)

    class BgpLsNlri:
        # https://datatracker.ietf.org/doc/html/rfc7752
        # https://datatracker.ietf.org/doc/html/rfc9085
        # https://datatracker.ietf.org/doc/html/rfc9086
        NODE = 1
        LINK = 2
        IPV4_PREFIX = 3
        IPV6_PREFIX = 4
        SR_POLICY = 5
        # PROTOCOL ID
        ISIS_LEVEL1 = 1
        ISIS_LEVEL2 = 2
        OSPFV2 = 3
        DIRECT = 4
        STATIC = 5
        OSPFV3 = 6
        BGP = 7
        RSVP = 8
        SR = 9

      
        def __init__(self, type, length):
            self.type = type
            self.length = length

        def parse_bin_data(self, nlri_bin_data):
            self.protocol_id, self.identifier = struct.unpack("!BQ", nlri_bin_data[:9])
            nlri_bin_data = nlri_bin_data[9:]
            self.descriptors = []
            while len(nlri_bin_data) > 0:
                descr = {}
                descr["type"], descr["length"] = struct.unpack("!HH", nlri_bin_data[:4])
                descr["nlri_type"] = self.type
                descr["nlri_protocol"] = self.protocol_id
                nlri_bin_data = nlri_bin_data[4:]
                descr_bin_data = nlri_bin_data[:descr["length"]]
                nlri_bin_data = nlri_bin_data[descr["length"]:]
                descriptor = self.Descriptor(**descr)
                descriptor.parse_bin_data(descr_bin_data)
                self.descriptors.append(descriptor)


        def set_bgp_ls_sr_policy_nlri(self, autonomous_system, bgp_ls_id, bgp_router_id, igp_router_id, protocol_origin, sr_policy_flags, sr_policy_endpoint, sr_policy_color):
            self.autonomous_system = autonomous_system
            self.bgp_ls_id = bgp_ls_id
            self.bgp_router_id = bgp_router_id
            self.igp_router_id = igp_router_id
            self.protocol_origin = protocol_origin
            self.sr_policy_flags = sr_policy_flags
            self.sr_policy_endpoint = sr_policy_endpoint
            self.sr_policy_color = sr_policy_color

            
        def generate(self):
            # https://datatracker.ietf.org/doc/html/rfc9857#section-4
            autonomous_system_tlv_bin = struct.pack("!HHL", BgpAttribute.BgpLsNlri.Descriptor.AUTONOMOUS_SYSTEM, 4, self.autonomous_system)
            bgp_identifier_tlv_bin = struct.pack("!HHL", BgpAttribute.BgpLsNlri.Descriptor.BGP_LS_IDENTIFIER, 4, 0)
            bgp_router_id_tlv_bin = struct.pack("!HH4s", BgpAttribute.BgpLsNlri.Descriptor.BGP_ROUTER_ID, 4, string_to_ip(self.bgp_router_id))
            if ":" in self.igp_router_id:
                igp_router_id_tlv_bin = struct.pack("!HH16s", BgpAttribute.BgpLsNlri.Descriptor.IPV6_TE_ROUTER_ID, 16, string_to_ip6(self.igp_router_id))
                local_descriptor_length = 44
            else:
                igp_router_id_tlv_bin = struct.pack("!HH4s", BgpAttribute.BgpLsNlri.Descriptor.IPV4_TE_ROUTER_ID, 4, string_to_ip(self.igp_router_id))
                local_descriptor_length = 32

            local_descriptor_bin = struct.pack("!HH", BgpAttribute.BgpLsNlri.Descriptor.LOCAL_NODE, local_descriptor_length)
            local_descriptor_bin += autonomous_system_tlv_bin
            local_descriptor_bin += bgp_identifier_tlv_bin
            local_descriptor_bin += bgp_router_id_tlv_bin
            local_descriptor_bin += igp_router_id_tlv_bin

            sr_policy_descriptor_length = 24
            if ":" in self.igp_router_id and ":" in self.sr_policy_endpoint:
                # ipv6 router-id and endpoint
                sr_policy_descriptor_length = 48
            elif ":" in self.igp_router_id:
                # ipv6 router-id, ipv4 endpoint
                sr_policy_descriptor_length = 36
            elif ":" in self.sr_policy_endpoint:
                # ipv4 router-id, ipv6 endpoint
                sr_policy_descriptor_length = 36

            if ":" in self.igp_router_id:
                originator_tlv_bin = struct.pack("!16s", string_to_ip6(self.igp_router_id))
            else:
                originator_tlv_bin = struct.pack("!4s", string_to_ip(self.igp_router_id))
            if ":" in self.sr_policy_endpoint:
                sr_endpoint_tlv_bin = struct.pack("!16s", string_to_ip6(self.sr_policy_endpoint))
            else:
                sr_endpoint_tlv_bin = struct.pack("!4s", string_to_ip(self.sr_policy_endpoint))
            
            sr_policy_descriptor_bin = struct.pack("!HHBBH", BgpAttribute.BgpLsNlri.Descriptor.SR_POLICY_CANDIDATE_PATH, sr_policy_descriptor_length, self.protocol_origin, self.sr_policy_flags, 0)
            sr_policy_descriptor_bin += sr_endpoint_tlv_bin
            sr_policy_descriptor_bin += struct.pack("!L", self.sr_policy_color)
            sr_policy_descriptor_bin += struct.pack("!L", self.autonomous_system)
            sr_policy_descriptor_bin += originator_tlv_bin
            # discriminator
            sr_policy_descriptor_bin += struct.pack("!L", 100)

            sr_policy_nlri_length = len(local_descriptor_bin) + len(sr_policy_descriptor_bin) + 9
            sr_policy_nlri_bin = struct.pack("!HHBQ", self.type, sr_policy_nlri_length, self.protocol_id, self.identifier)
            sr_policy_nlri_bin += local_descriptor_bin
            sr_policy_nlri_bin += sr_policy_descriptor_bin

            return sr_policy_nlri_bin
        





        class Descriptor:
            # TLV code points
            LOCAL_NODE = 256
            REMOTE_NODE = 257
            LINK_LOCAL_REMOTE = 258
            IPV4_INTERFACE_ADDRESS = 259
            IPV4_NEIGHBOR_ADDRESS = 260
            IPV6_INTERFACE_ADDRESS = 261
            IPV6_NEIGHBOR_ADDRESS = 262
            MULTI_TOPOLOGY_ID = 263
            OSPF_ROUTE_TYPE = 264
            IP_REACHABILITY = 265
            AUTONOMOUS_SYSTEM = 512
            BGP_LS_IDENTIFIER = 513
            OSPF_AREA_ID = 514
            IGP_ROUTER_ID = 515
            BGP_ROUTER_ID = 516
            BGP_CONFED_NUMBER = 517
            SR_POLICY_CANDIDATE_PATH = 554
            IPV4_TE_ROUTER_ID = 1028
            IPV6_TE_ROUTER_ID = 1029


            def __init__(self, type, length, nlri_type, nlri_protocol):
                self.type = type
                self.length = length
                self.nlri_type = nlri_type
                self.nlri_protocol = nlri_protocol

            def parse_node_descriptor(self, descr_bin_data):
                while len(descr_bin_data) > 0:
                    tlv_type, tlv_length = struct.unpack("!HH", descr_bin_data[:4])
                    descr_bin_data = descr_bin_data[4:]
                    if tlv_type == self.AUTONOMOUS_SYSTEM:
                        self.autonomous_system = struct.unpack("!L", descr_bin_data[:4])[0]
                    elif tlv_type == self.BGP_LS_IDENTIFIER:
                        self.bgp_ls_id = struct.unpack("!L", descr_bin_data[:4])[0]
                    elif tlv_type == self.OSPF_AREA_ID:
                        ospf_area_id_bin = struct.unpack("!4s", descr_bin_data[:4])[0]
                        self.ospf_area_id = ip_to_string(ospf_area_id_bin)
                    elif tlv_type == self.IGP_ROUTER_ID:
                        if self.nlri_protocol == BgpAttribute.BgpLsNlri.ISIS_LEVEL1 or self.nlri_protocol == BgpAttribute.BgpLsNlri.ISIS_LEVEL2:
                            self.igp_router_id = struct.unpack("!6s", descr_bin_data[:6])[0].hex('.', 2)
                            if len(descr_bin_data) > 6:
                                nsap = str(descr_bin_data[6]).zfill(2)
                                self.igp_router_id += f'.{nsap}'
                            else:
                                self.igp_router_id += f'.00'
                        elif self.nlri_protocol == BgpAttribute.BgpLsNlri.OSPFV2:
                            igp_router_id_bin = struct.unpack("!4s", descr_bin_data[:4])[0]
                            self.igp_router_id = ip_to_string(igp_router_id_bin)
                            if len(descr_bin_data) > 4:
                                ospf_dr_address_bin = struct.unpack("!4s", descr_bin_data[4:8])[0]
                                self.ospf_dr_address = ip_to_string(ospf_dr_address_bin)
                        else:
                            self.igp_router_id = None
                    elif tlv_type == self.BGP_ROUTER_ID:
                        bgp_router_id_bin = struct.unpack("!4s", descr_bin_data[:4])[0]
                        self.bgp_router_id = ip_to_string(bgp_router_id_bin)
                    descr_bin_data = descr_bin_data[tlv_length:]

            def parse_link_local_remote(self, descr_bin_data):
                self.local_link_id, self.remote_link_id = struct.unpack("!LL", descr_bin_data)

            def parse_ipv4_interface_address(self, descr_bin_data):
                ip_address_bin = struct.unpack("!4s", descr_bin_data)[0]
                self.ipv4_interface_address = ip_to_string(ip_address_bin)

            def parse_ipv4_neighbor_address(self, descr_bin_data):
                ip_address_bin = struct.unpack("!4s", descr_bin_data)[0]
                self.ipv4_neighbor_address = ip_to_string(ip_address_bin)

            def parse_ipv6_interface_address(self, descr_bin_data):
                ip_address_bin = struct.unpack("!16s", descr_bin_data)[0]
                self.ipv6_interface_address = ip6_to_string(ip_address_bin)
                
            def parse_ipv6_neighbor_address(self, descr_bin_data):
                ip_address_bin = struct.unpack("!16s", descr_bin_data)[0]
                self.ipv6_neighbor_address = ip6_to_string(ip_address_bin)

            def parse_multi_topology_id(self, descr_bin_data):
                self.multi_topology_id = []
                while len(descr_bin_data) > 0:
                    mt_id = struct.unpack("!H", descr_bin_data[:2])[0]
                    self.multi_topology_id.append(mt_id)
                    descr_bin_data = descr_bin_data[2:]

            def parse_ospf_route_type(self, descr_bin_data):
                self.ospf_route_type = struct.unpack("!B", descr_bin_data[:1])[0]

            def parse_ipv4_reachability(self, descr_bin_data):
                prefix_length = struct.unpack("!B", descr_bin_data[:1])[0]
                descr_bin_data = descr_bin_data[1:]
                prefix_bin = b""
                while len(descr_bin_data) > 0:
                    prefix_bin += struct.unpack("!1s", descr_bin_data[:1])[0]
                    descr_bin_data = descr_bin_data[1:]
                while len(prefix_bin) < 4:
                    prefix_bin += b"\00"
                self.prefix = ip_to_string(prefix_bin) + "/" + str(prefix_length)

            def parse_ipv6_reachability(self, descr_bin_data):
                prefix_length = struct.unpack("!B", descr_bin_data[:1])[0]
                descr_bin_data = descr_bin_data[1:]
                prefix_bin = b""
                while len(descr_bin_data) > 0:
                    prefix_bin += struct.unpack("!1s", descr_bin_data[:1])[0]
                    descr_bin_data = descr_bin_data[1:]
                while len(prefix_bin) < 16:
                    prefix_bin += b"\00"
                self.prefix = ip6_to_string(prefix_bin) + "/" + str(prefix_length)

            def parse_ip_reachability(self, descr_bin_data):
                if self.nlri_type == BgpAttribute.BgpLsNlri.IPV4_PREFIX:
                    self.parse_ipv4_reachability(descr_bin_data)
                elif self.nlri_type == BgpAttribute.BgpLsNlri.IPV6_PREFIX:
                    self.parse_ipv6_reachability(descr_bin_data)


            DESCRIPTOR_PARSERS = {
                LINK_LOCAL_REMOTE: parse_link_local_remote,
                LOCAL_NODE: parse_node_descriptor,
                REMOTE_NODE: parse_node_descriptor,
                LINK_LOCAL_REMOTE: parse_link_local_remote,
                IPV4_INTERFACE_ADDRESS: parse_ipv4_interface_address,
                IPV4_NEIGHBOR_ADDRESS: parse_ipv4_neighbor_address,
                IPV6_INTERFACE_ADDRESS: parse_ipv6_interface_address,
                IPV6_NEIGHBOR_ADDRESS: parse_ipv6_neighbor_address,
                MULTI_TOPOLOGY_ID: parse_multi_topology_id,
                OSPF_ROUTE_TYPE: parse_ospf_route_type,
                IP_REACHABILITY: parse_ip_reachability
            }

            def parse_bin_data(self, descr_bin_data):
                if self.type in self.DESCRIPTOR_PARSERS:
                    func = self.DESCRIPTOR_PARSERS[self.type]
                    func(self, descr_bin_data)
    
    def parse_bgp_lu_nlri(self, afi, attr_bin_data):
        self.bgp_lu_nlris = []
        while len(attr_bin_data) > 0:
            # length is in bits but we need bytes
            nlri_length_bits = struct.unpack("!B", attr_bin_data[:1])[0]
            if nlri_length_bits % 8 == 0:
                nlri_length = nlri_length_bits // 8
            else:
                nlri_length = nlri_length_bits // 8 + (8 - nlri_length_bits % 8)
            attr_bin_data = attr_bin_data[1:]
            nlri_bin_data = attr_bin_data[:nlri_length]
            attr_bin_data = attr_bin_data[nlri_length:]
            bgp_lu_nlri = self.BgpLuNlri(afi, nlri_length_bits)
            bgp_lu_nlri.parse_bin_data(nlri_bin_data)
            self.bgp_lu_nlris.append(bgp_lu_nlri)

    # https://www.rfc-editor.org/rfc/rfc3107
    class BgpLuNlri:
        def __init__(self, afi, nlri_length_bits):
            self.afi = afi
            self.nlri_length_bits = nlri_length_bits
            self.label_stack = []
            self.prefix = None

        def parse_bin_data(self, nlri_bin_data):
            while len(nlri_bin_data) > 0:
                label = struct.unpack("!3s", nlri_bin_data[:3])[0].hex()
                label = int(label, 16)
                label_value = label >> 4
                _ = (label_value >> 1) & 0b111
                bos = label & 0b1
                self.label_stack.append(label_value)
                nlri_bin_data = nlri_bin_data[3:]
                self.nlri_length_bits -= 24
                if bos == 1: break
            prefix_bin = b""
            while len(nlri_bin_data) > 0:
                prefix_bin += struct.unpack("!1s", nlri_bin_data[:1])[0]
                nlri_bin_data = nlri_bin_data[1:]
            if self.afi == BgpCapability.BgpAfi.IPV4:
                while len(prefix_bin) < 4:
                    prefix_bin += b"\00"
                self.prefix = ip_to_string(prefix_bin) + "/" + str(self.nlri_length_bits)
            elif self.afi == BgpCapability.BgpAfi.IPV6:
                while len(prefix_bin) < 16:
                    prefix_bin += b"\00"
                self.prefix = ip6_to_string(prefix_bin) + "/" + str(self.nlri_length_bits)

        def set_bgp_lu_nlri(self, label_stack, prefix):
            self.label_stack = label_stack
            self.prefix = prefix

        def generate(self):
            nlri_bin = struct.pack("!B", self.nlri_length_bits)
            label_stack = copy.copy(self.label_stack)
            while len(label_stack) > 0:
                label_value = label_stack.pop(0)
                bos = 0
                if len(label_stack) == 0:
                    bos = 1
                label = (label_value << 4) | bos
                binary_data = struct.pack("!I", label)
                binary_data = binary_data[-3:]
                nlri_bin += binary_data
            
            if self.afi == BgpCapability.BgpAfi.IPV4:
                nlri_bin += struct.pack("!4s", string_to_ip(self.prefix))
            else:
                nlri_bin += struct.pack("!16s", string_to_ip6(self.prefix))
            
            return nlri_bin



    class BgpSrteNlri:
        # https://datatracker.ietf.org/doc/html/draft-ietf-idr-segment-routing-te-policy-20
        def __init__(self, nlri_length, distinguisher, color, endpoint):
            self.nlri_length = nlri_length
            self.distinguisher = distinguisher
            self.color = color
            self.endpoint = endpoint

        def generate(self):
            if ":" in self.endpoint:
                return struct.pack("!BLL16s", self.nlri_length, self.distinguisher, self.color, string_to_ip6(self.endpoint))
            else:
                return struct.pack("!BLL4s", self.nlri_length, self.distinguisher, self.color, string_to_ip(self.endpoint))


    parsers = {
        ORIGIN: parse_origin,
        AS_PATH: parse_as_path,
        MULTI_EXIT_DISC: parse_multi_exit_disc,
        LOCAL_PREF: parse_local_pref,
        ORIGINATOR_ID: parse_originator_id,
        CLUSTER_LIST: parse_cluster_list,
        LARGE_COMMUNITY: parse_large_community,
        MP_REACH_NLRI: parse_mp_reach_nlri,
        MP_UNREACH_NLRI: parse_mp_unreach_nlri,
        BGP_LS: parse_bgp_ls_attribute
    }

    def parse_bin_data(self, attr_bin_data):
        if self.type_code in self.parsers.keys():
            func = self.parsers[self.type_code]
            func(self, attr_bin_data)


    def set_origin(self, origin):
        self.origin = origin

    def set_as_path(self, as_set, as_sequence, asn32=False):
        self.as_set = as_set
        self.as_sequence = as_sequence
        self.asn32 = asn32

    def set_local_pref(self, local_pref):
        self.local_pref = local_pref
            
    def set_mp_reach_nlri(self, afi, safi, next_hop_length, next_hop, nlri):
        self.afi = afi
        self.safi = safi
        self.next_hop_length = next_hop_length
        self.next_hop = next_hop
        self.nlri = nlri

    def set_mp_unreach_nlri(self, afi, safi, nlri):
        self.afi = afi
        self.safi = safi
        self.nlri = nlri

    def set_tunnel_encap(self, tunnel_type, path_preference, binding_sid, policy_name, enlp, sid_lists):
        self.tunnel_type = tunnel_type
        self.path_preference = path_preference
        self.binding_sid = binding_sid
        self.policy_name = policy_name
        self.enlp = enlp
        self.sid_lists = sid_lists
        #self.sid_weight = sid_weight
        #self.segment_list = segment_list

    def set_rt_extcommunity(self, target_router_id):
        self.target_router_id = target_router_id

    def set_sr_policy_bgp_ls_attribute(self, bandwidth_constraint):
        self.bandwidth_constraint = bandwidth_constraint

    def generate_origin(self):
        return struct.pack("!B", self.origin)
    
    def generate_as_path(self):
        as_num = len(self.as_sequence)
        if as_num == 0:
            return b""
            #return struct.pack("!BB", 2, as_num)
        as_path_bin = struct.pack("!BB", 2, as_num)
        if self.asn32:
            for asn in self.as_sequence:
                as_path_bin += struct.pack("!L", asn)
        else:
            for asn in self.as_sequence:
                as_path_bin += struct.pack("!H", asn)     
        return as_path_bin
    
    def generate_local_pref(self):
        return struct.pack("!L", self.local_pref)
    
    def generate_mp_reach_nlri(self):
        if self.next_hop_length == 4:
            mp_reach_nlri_bin = struct.pack("!HBB4sB", self.afi, self.safi, self.next_hop_length, string_to_ip(self.next_hop), 0)
        elif self.next_hop_length == 16:
            mp_reach_nlri_bin = struct.pack("!HBB16sB", self.afi, self.safi, self.next_hop_length, string_to_ip6(self.next_hop), 0)
        mp_reach_nlri_bin += self.nlri.generate()
        return mp_reach_nlri_bin
    
    def generate_mp_unreach_nlri(self):
        mp_unreach_nlri_bin = struct.pack("!HB", self.afi, self.safi)
        mp_unreach_nlri_bin += self.nlri.generate()
        return mp_unreach_nlri_bin
    
    def generate_tunnel_encap(self):
        tunnel_encap_bin = struct.pack("!H", self.tunnel_type)
        tunnel_encap_length = 0

        path_preference_bin = struct.pack("!BBBBL", 12, 6, 0, 0, self.path_preference)
        tunnel_encap_length += len(path_preference_bin)

        binding_sid_bin = None
        if self.binding_sid:
            binding_sid_bin = struct.pack("!BBBBL", 13, 6, 0, 0, self.binding_sid*4096)
            tunnel_encap_length += len(binding_sid_bin)
        # srv6 bsid test
        #binding_sid_bin = struct.pack("!BBBB16s", 20, 18, 0, 0, string_to_ip6(self.binding_sid))

        # Advertising policy name TLV is disabled due to IOS-XR Bug
        # When XR route reflector receives SR-TE route with TLV it doesn't understand,
        # It advertises it further without those TLV but with original attribute length
        # resulting in malformed packet
        #policy_name_encoded = self.policy_name.encode('utf-8')
        #policy_name_bin = struct.pack("!BHB", 130, len(policy_name_encoded)+1, 0)
        #policy_name_bin += policy_name_encoded
        #tunnel_encap_length += len(policy_name_bin)

        # https://datatracker.ietf.org/doc/html/draft-ietf-idr-segment-routing-te-policy-26#section-2.4.5

        ENLP_CODES = {
            "ipv4": 1,
            "ipv6": 2,
            "both": 3,
            "none": 4
        }

        enlp_bin = None
        if self.enlp:
            enlp_code = ENLP_CODES[self.enlp]
            enlp_bin = struct.pack("!BBBBB", 14, 3, 0, 0, enlp_code)
            tunnel_encap_length += len(enlp_bin)

        # https://datatracker.ietf.org/doc/html/draft-ietf-idr-segment-routing-te-policy-26#section-2.4.4

        sid_lists_bin = []
        for sid_list in self.sid_lists:
            sid_weight_bin = struct.pack("!BBBBL", 9, 6, 0, 0, 1)
            segment_list_encoded = b""
            for segment in sid_list:
                segment_bin = struct.pack("!BBBBL", 1, 6, 0, 0, segment*4096)
                # test SRv6 sid type b
                #segment_bin = struct.pack("!BBBB16s", 13, 18, 0, 0, string_to_ip6(segment))
                segment_list_encoded += segment_bin
            segment_list_bin = struct.pack("!B", 128)
            segment_list_bin += struct.pack("!H", len(segment_list_encoded) + 9)
            segment_list_bin += struct.pack("!B", 0)
            segment_list_bin += sid_weight_bin
            segment_list_bin += segment_list_encoded
            sid_lists_bin.append(segment_list_bin)
            tunnel_encap_length += len(segment_list_bin)

        tunnel_encap_bin += struct.pack("!H", tunnel_encap_length)
        tunnel_encap_bin += path_preference_bin
        if binding_sid_bin:
            tunnel_encap_bin += binding_sid_bin
        #tunnel_encap_bin += policy_name_bin
        if enlp_bin:
            tunnel_encap_bin += enlp_bin
        for sid_list_bin in sid_lists_bin:
            tunnel_encap_bin += sid_list_bin

        return tunnel_encap_bin
    

    def generate_noadv_community(self):
        return struct.pack("!L", 4294967042)
    

    def generate_rt_extcommunity(self):
        return struct.pack("!BB4sH", 1, 2, string_to_ip(self.target_router_id), 0)

    def generate_sr_policy_bgp_ls_attribute(self):
        # for now this only returns sampled bandwidth rate
        bytes_per_sec = self.bandwidth_constraint / 8.0
        # Pack as IEEE-754 float (big-endian)
        ieee_bytes = struct.pack('>f', bytes_per_sec)
        bandwidth_constraint_tlv = struct.pack("!HH", BgpAttribute.LinkStateTlv.SR_BANDWIDTH_CONSTRAINT, 4)
        bandwidth_constraint_tlv += ieee_bytes
        return bandwidth_constraint_tlv
    
    generators = {
        ORIGIN: generate_origin,
        AS_PATH: generate_as_path,
        LOCAL_PREF: generate_local_pref,
        MP_REACH_NLRI: generate_mp_reach_nlri,
        MP_UNREACH_NLRI: generate_mp_unreach_nlri,
        TUNNEL_ENCAP: generate_tunnel_encap,
        COMMUNITY: generate_noadv_community,
        EXT_COMMUNITIES: generate_rt_extcommunity,
        BGP_LS: generate_sr_policy_bgp_ls_attribute
    }

    def generate(self):
        if self.type_code in self.generators.keys():
            func = self.generators[self.type_code]
            return func(self)



















class BgpNotification(BgpMessage):
    MESSAGE_TYPE = BgpMessage.NOTIFICATION
    MESSAGE_HEADER_ERROR = 1
    OPEN_MESSAGE_ERROR = 2
    UPDATE_MESSAGE_ERROR = 3
    HOLD_TIMER_EXPIRED = 4
    FINITE_STATE_MACHINE_ERROR = 5
    CEASE = 6
    # Message header error subcodes
    CONNECTION_NOT_SYNCHRONIZED = 1
    BAD_MESSAGE_LENGTH = 2
    BAD_MESSAGE_TYPE = 3
    # OPEN message error subcodes
    UNSUPPORTED_VERSION_NUMBER = 1
    BAD_PEER_AS = 2
    BAD_BGP_IDENTIFIER = 3
    UNSUPPORTED_OPTIONAL_PARAMETER = 4
    UNACCEPTABLE_HOLD_TIME = 6
    UNSUPPORTED_CAPABILITY = 7
    ROLE_MISMATCH = 11
    # Update message error subcodes
    MALFORMED_ATTRIBUTE_LIST = 1
    UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE = 2
    MISSING_WELL_KNOWN_ATTRIBUTE = 3
    ATTRIBUTE_FLAGS_ERROR = 4
    ATTRIBUTE_LENGTH_ERROR = 5
    INVALID_ORIGIN_ATTRIBUTE = 6
    INVALID_NEXT_HOP_ATTRIBUTE = 8
    OPTIONAL_ATTRIBUTE_ERROR = 9
    INVALID_NETWORK_FIELD = 10
    MALFORMED_AS_PATH = 11
    # FSM error subcodes
    UNEXPECTED_MESSAGE_OPENSENT_STATE = 1
    UNEXPECTED_MESSAGE_OPENCONFIRM_STATE = 2
    UNEXPECTED_MESSAGE_ESTABLISHED_STATE = 3
    # Cease subcodes
    MAX_NUMBER_PREFIXES_REACHED = 1
    ADMIN_SHUTDOWN = 2
    PEER_DECONFIGURED = 3
    ADMIN_RESET = 4
    CONNECTION_REJECTED = 5
    OTHER_CONFIG_CHANGE = 6
    CONNECTION_COLLISION_RESOLUTION = 7
    OUT_OF_RESOURCES = 8
    HARD_RESET = 9
    BFD_DOWN = 10

    def __init__(self, error_code, error_subcode, data=b""):
        self.error_code = error_code
        self.error_subcode = error_subcode
        self.data = data

    @classmethod
    def parse(cls, message_data):
        error_code, error_subcode = struct.unpack("!BB", message_data[:2])
        data = message_data[2:]
        return cls(error_code, error_subcode, data)

    def generate(self):
        return struct.pack("!BB", self.error_code, self.error_subcode)

    @staticmethod
    def get_error_code(error_code):
        ERROR_CODES = {
            BgpNotification.MESSAGE_HEADER_ERROR: "Message Header Error",
            BgpNotification.OPEN_MESSAGE_ERROR: "Open Message Error",
            BgpNotification.UPDATE_MESSAGE_ERROR: "Update Message Error",
            BgpNotification.HOLD_TIMER_EXPIRED: "Hold Timer Expired",
            BgpNotification.FINITE_STATE_MACHINE_ERROR: "FSM Error",
            BgpNotification.CEASE: "Cease"
        }
        if error_code in ERROR_CODES.keys():
            return ERROR_CODES[error_code]
        return error_code
        
    @staticmethod
    def get_error_subcode(error_code, error_subcode):
        MESSAGE_HEADER_ERRORS = {
            BgpNotification.CONNECTION_NOT_SYNCHRONIZED: "Connection Not Synchronized",
            BgpNotification.BAD_MESSAGE_LENGTH: "Bad Message Length",
            BgpNotification.BAD_MESSAGE_TYPE: "Bad Message Type"
        }
        OPEN_MESSAGE_ERRORS = {
            BgpNotification.UNSUPPORTED_VERSION_NUMBER: "Unsupported Version Number",
            BgpNotification.BAD_PEER_AS: "Bad Peer AS",
            BgpNotification.BAD_BGP_IDENTIFIER: "Bad BGP Identifier",
            BgpNotification.UNSUPPORTED_OPTIONAL_PARAMETER: "Unsupported Optional Parameter",
            BgpNotification.UNACCEPTABLE_HOLD_TIME: "Unacceptable Hold Time",
            BgpNotification.UNSUPPORTED_CAPABILITY: "Unsupported Capability",
            BgpNotification.ROLE_MISMATCH: "Role Mismatch"
        }
        UPDATE_MESSAGE_ERRORS = {
            BgpNotification.MALFORMED_ATTRIBUTE_LIST: "Malformed Attribute List",
            BgpNotification.UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE: "Unrecognized Well Known Attribute",
            BgpNotification.MISSING_WELL_KNOWN_ATTRIBUTE: "Missing Well Known Attribute",
            BgpNotification.ATTRIBUTE_FLAGS_ERROR: "Attribute Flags Error",
            BgpNotification.ATTRIBUTE_LENGTH_ERROR: "Attribute Length Error",
            BgpNotification.INVALID_ORIGIN_ATTRIBUTE: "Invalid Origin Attribute",
            BgpNotification.INVALID_NEXT_HOP_ATTRIBUTE: "Invalid Next Hop Attribute",
            BgpNotification.OPTIONAL_ATTRIBUTE_ERROR: "Optional Attribute Error",
            BgpNotification.INVALID_NETWORK_FIELD: "Invalid Network Field",
            BgpNotification.MALFORMED_AS_PATH: "Malformed AS Path"
        }
        FSM_ERRORS = {
            BgpNotification.UNEXPECTED_MESSAGE_OPENSENT_STATE: "Unexpected Message in OpenSent State",
            BgpNotification.UNEXPECTED_MESSAGE_OPENCONFIRM_STATE: "Unexpected Message in OpenConfirm State",
            BgpNotification.UNEXPECTED_MESSAGE_ESTABLISHED_STATE: "Unexpected Message in Established State",
        }
        CEASES = {
            BgpNotification.MAX_NUMBER_PREFIXES_REACHED: "Maximum Number of Prefixes Reached",
            BgpNotification.ADMIN_SHUTDOWN: "Admin Shutdown",
            BgpNotification.PEER_DECONFIGURED: "Peer Deconfigured",
            BgpNotification.ADMIN_RESET: "Admin Reset",
            BgpNotification.CONNECTION_REJECTED: "Connection Rejected",
            BgpNotification.OTHER_CONFIG_CHANGE: "Other Config Change",
            BgpNotification.CONNECTION_COLLISION_RESOLUTION: "Connection Collision Resolution",
            BgpNotification.OUT_OF_RESOURCES: "Out of Resources",
            BgpNotification.HARD_RESET: "Hard Reset",
            BgpNotification.BFD_DOWN: "BFD Down"
        }
        ERROR_SUBCODES = {
            BgpNotification.MESSAGE_HEADER_ERROR: MESSAGE_HEADER_ERRORS,
            BgpNotification.OPEN_MESSAGE_ERROR: OPEN_MESSAGE_ERRORS,
            BgpNotification.UPDATE_MESSAGE_ERROR: UPDATE_MESSAGE_ERRORS,
            BgpNotification.FINITE_STATE_MACHINE_ERROR: FSM_ERRORS,
            BgpNotification.CEASE: CEASES
        }

        if error_code in ERROR_SUBCODES.keys():
            if error_subcode in ERROR_SUBCODES[error_code].keys():
                return ERROR_SUBCODES[error_code][error_subcode]
        return error_subcode


class BgpKeepalive(BgpMessage):
    MESSAGE_TYPE = BgpMessage.KEEPALIVE

    @staticmethod
    def generate():
        return b""

class BgpRouteRefresh(BgpMessage):
    MESSAGE_TYPE = BgpMessage.ROUTE_REFRESH

    def __init__(self, afi, safi):
        self.afi = afi
        self.safi = safi

    @classmethod
    def parse(cls, message_data):
        afi, _, safi = struct.unpack("!HBB", message_data[:4])
        return cls(afi, safi)
    
    def generate(self):
        return struct.pack("!HBB", self.afi, 0, self.safi)


class BgpMessageParser:
    def __init__(self, message_type, message_data):
        self.message_type = message_type
        self.message_data = message_data


    def parse(self):
        if self.message_type == BgpMessage.OPEN:
            return BgpOpen.parse(self.message_data)
        elif self.message_type == BgpMessage.UPDATE:
            return BgpUpdate.parse(self.message_data)
        elif self.message_type == BgpMessage.NOTIFICATION:
            return BgpNotification.parse(self.message_data)
        elif self.message_type == BgpMessage.KEEPALIVE:
            return None
        elif self.message_type == BgpMessage.ROUTE_REFRESH:
            return BgpRouteRefresh.parse(self.message_data)