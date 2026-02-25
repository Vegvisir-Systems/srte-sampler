#!/usr/bin/env python3

from pprint import pprint
from datetime import datetime, timedelta
from time import time
import ipaddress


from bgp.bgp_message import *

intervals = (
    ('years', 31536000), # 60 * 60 * 24 * 365
    ('weeks', 604800),  # 60 * 60 * 24 * 7
    ('days', 86400),    # 60 * 60 * 24
    ('hours', 3600),    # 60 * 60
    ('minutes', 60),
    ('seconds', 1),
)

def display_uptime(uptime, granularity=6):
    uptime_list = uptime.split(":")
    uptime_seconds = int(uptime_list[0]) * 3600 + int(uptime_list[1]) * 60 + int(uptime_list[2])
    result = []

    for name, count in intervals:
        value = uptime_seconds // count
        if value:
            uptime_seconds -= value * count
            if value == 1:
                name = name.rstrip('s')
            result.append("{} {}".format(value, name))
    return ', '.join(result[:granularity])


def print_show_version(input):
    output = (
        f'{input["model_name"]} by {input["mfg_name"]}\n'
        f'\n'
        f'Software version: {input["version"]}\n'
        f'Image build date: {input["build_date"]}\n'
        f'\n'
        f'System start time: {datetime.fromtimestamp(input["start_time"]).strftime("%B %d, %Y %H:%M:%S")}\n'
        f'Uptime: {input["uptime"]}\n'
        f'\n'
        f'Documentation: https://vegvisir.ie/documentation/\n'
        f'Support: support@vegvisir.ie\n'
        f'\n'
    )

    return output
  

def print_show_threads(input):
    if type(input["command_server_keepalive"]) == int:
        command_server_keepalive = f'{input["command_server_keepalive"]} seconds ago'
    else:
        command_server_keepalive = f'{input["command_server_keepalive"]}'
    if type(input["syslog_config_update_keepalive"]) == int:
        syslog_config_update_keepalive = f'{input["syslog_config_update_keepalive"]} seconds ago'
    else:
        syslog_config_update_keepalive = f'{input["syslog_config_update_keepalive"]}'
    if type(input["mgmt_config_update_keepalive"]) == int:
        mgmt_config_update_keepalive = f'{input["mgmt_config_update_keepalive"]} seconds ago'
    else:
        mgmt_config_update_keepalive = f'{input["mgmt_config_update_keepalive"]}'
    if type(input["bgp_config_update_keepalive"]) == int:
        bgp_config_update_keepalive = f'{input["bgp_config_update_keepalive"]} seconds ago'
    else:
        bgp_config_update_keepalive = f'{input["bgp_config_update_keepalive"]}'
    if type(input["bgp_signal_receiver_keepalive"]) == int:
        bgp_signal_receiver_keepalive = f'{input["bgp_signal_receiver_keepalive"]} seconds ago'
    else:
        bgp_signal_receiver_keepalive = f'{input["bgp_signal_receiver_keepalive"]}'
    if type(input["bgp_ls_loc_rib_keepalive"]) == int:
        bgp_ls_loc_rib_keepalive = f'{input["bgp_ls_loc_rib_keepalive"]} seconds ago'
    else:
        bgp_ls_loc_rib_keepalive = f'{input["bgp_ls_loc_rib_keepalive"]}'
    if type(input["sampling_config_update_keepalive"]) == int:
        sampling_config_update_keepalive = f'{input["sampling_config_update_keepalive"]} seconds ago'
    else:
        sampling_config_update_keepalive = f'{input["sampling_config_update_keepalive"]}'
    if type(input["sampling_gnmi_streaming_keepalive"]) == int:
        sampling_gnmi_streaming_keepalive = f'{input["sampling_gnmi_streaming_keepalive"]} seconds ago'
    else:
        sampling_gnmi_streaming_keepalive = f'{input["sampling_gnmi_streaming_keepalive"]}'
    if type(input["sampling_calculate_bandwidth_keepalive"]) == int:
        sampling_calculate_bandwidth_keepalive = f'{input["sampling_calculate_bandwidth_keepalive"]} seconds ago'
    else:
        sampling_calculate_bandwidth_keepalive = f'{input["sampling_calculate_bandwidth_keepalive"]}'
    if type(input["sampling_cleanup_old_policies_keepalive"]) == int:
        sampling_cleanup_old_policies_keepalive = f'{input["sampling_cleanup_old_policies_keepalive"]} seconds ago'
    else:
        sampling_cleanup_old_policies_keepalive = f'{input["sampling_cleanup_old_policies_keepalive"]}'


    output = (
        f'Traffic Dictator threads stats\n'
        f'\n'
        f'  {"Thread name":<30} {"Status":<20} {"Last keepalive":<20}\n'
        f'  {"-----------":<30} {"------":<20} {"--------------":<20}\n'
        f'  {"Command server":<30} {input["command_server_status"]:<20} {command_server_keepalive:<20}\n'
        f'  {"Syslog config updater":<30} {input["syslog_config_update_status"]:<20} {syslog_config_update_keepalive:<20}\n'
        f'  {"Management config updater":<30} {input["mgmt_config_update_status"]:<20} {mgmt_config_update_keepalive:<20}\n'
        f'  {"BGP config updater":<30} {input["bgp_config_update_status"]:<20} {bgp_config_update_keepalive:<20}\n'
        f'  {"BGP signal receiver":<30} {input["bgp_signal_receiver_status"]:<20} {bgp_signal_receiver_keepalive:<20}\n'
        f'  {"BGP LS LocRib":<30} {input["bgp_ls_loc_rib_status"]:<20} {bgp_ls_loc_rib_keepalive:<20}\n'
        f'  {"Sampling config updater":<30} {input["sampling_config_update_status"]:<20} {sampling_config_update_keepalive:<20}\n'
        f'  {"Sampling GNMI streamer":<30} {input["sampling_gnmi_streaming_status"]:<20} {sampling_gnmi_streaming_keepalive:<20}\n'
        f'  {"Sampling bandwidth calculator":<30} {input["sampling_calculate_bandwidth_status"]:<20} {sampling_calculate_bandwidth_keepalive:<20}\n'
        f'  {"Sampling old policy cleaner":<30} {input["sampling_cleanup_old_policies_status"]:<20} {sampling_cleanup_old_policies_keepalive:<20}\n'
    )

    return output[:-1]


def print_show_running_config(input):
    input.append("end")
    return '\n'.join(input)


def print_show_bgp_summary(input):
    output = ( 
        f'BGP summary information\n'
        f'Router identifier {input["router_id"]}, local AS number {input["asn"]}\n'
        f'  {"Neighbor":20} {"V":4} {"AS":10} {"MsgRcvd":>8} {"MsgSent":>8} {"InQ":>8} {"OutQ":>8}      {"Up/Down":10} {"State":12} {"Received NLRI":>15}    {"Active AF"}\n'
    )
    for peer in input["peers"].keys():
        peer_ip = peer
        peer_asn = str(input["peers"][peer]["asn"])
        msg_received = str(input["peers"][peer]["msg_received"])
        msg_sent = str(input["peers"][peer]["msg_sent"])
        in_msg_queue = str(input["peers"][peer]["in_msg_queue"])
        out_msg_queue = str(input["peers"][peer]["out_msg_queue"])
        last_up_down = input["peers"][peer]["last_up_down"]
        if not last_up_down: 
            last_up_down = "Never"
        last_up_down = str(last_up_down)
        if "day" in last_up_down:
            # then print <days>d<hours>h
            num_days = last_up_down.split()[0]
            num_hours = last_up_down.split()[2].split(":")[0]
            last_up_down = f'{num_days}d{num_hours}h'
        if input["peers"][peer]["admin_down"]:
            peer_state = "Idle(Admin)"
            if input["peers"][peer]["pfx_limit_exceeded"]:
                peer_state = "Idle(PfxLim)"
        else:
            peer_state = input["peers"][peer]["peer_state"]
        negotiated_afs = ', '.join(input["peers"][peer]["address_families"])
        received_nlri = input["peers"][peer]["nlri_received"] 
        peer_string = f'  {peer_ip:20} {"4":4} {peer_asn:10} {msg_received:>8} {msg_sent:>8} {in_msg_queue:>8} {out_msg_queue:>8}      {last_up_down:10} {peer_state:12} {received_nlri:>15}    {negotiated_afs}\n'
        output += peer_string

    return output[:-1]



def print_show_bgp_neighbors(input):
    output = ""
    for peer in input["peer_list"]:
        if not peer["hold_time_left"]:
            hold_time_left = "Hold timer is inactive"
        else:
            hold_time_left = "Hold timer is active, time left " +  peer["hold_time_left"]
        if not peer["keepalive_time_left"]: 
            keepalive_time_left = "Keepalive timer is inactive"
        else:
            keepalive_time_left = "Keepalive timer is active, time left " + peer["keepalive_time_left"]
        if not peer["connect_retry_time_left"]: 
            connect_retry_time_left = "Connect timer is inactive"
        else:
            connect_retry_time_left = "Connect timer is active, time left " + peer["connect_retry_time_left"]
        if not peer["idle_hold_time_left"]: 
            idle_hold_time_left = "Idle hold timer is inactive"
        else:
            idle_hold_time_left = "Idle hold timer is active, time left " + peer["idle_hold_time_left"]

        if peer["admin_down"]:
            peer_state = "Idle(Admin)"
            if peer["pfx_limit_exceeded"]:
                peer_state = "Idle(PfxLim)"
        else:
            peer_state = peer["state"]

        if peer["last_up_down"]:
            if peer_state == "Established":
                up_down = ", up for "
            else:
                up_down = ", down for "
            up_down += str(peer["last_up_down"])
        else:
            up_down = ""

        negotiated_afs = ', '.join(peer["address_families"])
        other_capabilities = ', '.join(peer["other_capabilities"])

        peer_string = (
            f'BGP neighbor is {peer["peer_address"]}, port {peer["config_remote_port"]} remote AS {str(peer["asn"])}, {peer["link_type"]} link\n'
            f'  BGP version {str(peer["negotiated_version"])}, remote router ID {peer["router_id"]}\n'
            f'  Last read {peer["last_received"]}, last write {peer["last_sent"]}\n'
            f'  Hold time is {str(peer["hold_time"])}, keepalive interval is {str(peer["keepalive_time"])} seconds\n'
            f'  Configured hold time is {str(peer["config_hold_time"])}, keepalive interval is {str(peer["config_keepalive_time"])} seconds\n'
            f'  {hold_time_left}\n'
            f'  {keepalive_time_left}\n'
            f'  {connect_retry_time_left}\n'
            f'  {idle_hold_time_left}\n'
            f'  BGP state is {peer_state}{up_down}\n'
            f'  Number of transitions to established: {peer["established_transitions"]}\n'
            f'  Last state was {peer["last_state"]}\n'
            #f'  Last event was Start\n'
            #f'  Last rcvd socket-error:Connection reset by peer, Last time 00:04:11, First time 00:42:38, Repeats 3\n'
            f'\n'
            f'  Active address families:\n'
            f'    {negotiated_afs}\n'
            f'\n'
            f'\n'
            f'  Other negotiated capabilities:\n'
            f'    {other_capabilities}\n'
            f'\n'
            f'{"Sent":>29} {"Rcvd":>10}\n'
            f'    Opens: {str(peer["out_msg_stats"]["opens"]):>18} {str(peer["in_msg_stats"]["opens"]):>10}\n'
            f'    Notifications: {str(peer["out_msg_stats"]["notifications"]):>10} {str(peer["in_msg_stats"]["notifications"]):>10}\n'
            f'    Updates: {str(peer["out_msg_stats"]["updates"]):>16} {str(peer["in_msg_stats"]["updates"]):>10}\n'
            f'    Keepalives: {str(peer["out_msg_stats"]["keepalives"]):>13} {str(peer["in_msg_stats"]["keepalives"]):>10}\n'
            f'    Route Refresh: {str(peer["out_msg_stats"]["route_refreshes"]):>10} {str(peer["in_msg_stats"]["route_refreshes"]):>10}\n'
            f'\n'
            f'    Total messages: {str(peer["sent_messages"]):>9} {str(peer["received_messages"]):>10}\n'
            f'\n'
            f'  NLRI statistics:\n'
            f'{"Sent":>40} {"Rcvd":>10}\n'
            f'    Link-State: {str(peer["ls_nlri_sent"]):>24} {str(peer["ls_nlri_received"]):>10}\n'
            f'Local IP is {peer["local_address"]}, local AS is {peer["local_asn"]}, local router ID {peer["local_router_id"]}\n'
            f'TTL is {peer["ttl"]}\n'
        )
        if peer["passive"]:
            peer_string += f'Passive TCP connection-mode is enabled\n'
        output += peer_string

    return output[:-1]


def print_show_bgp_link_state(input):
    output = (
        f'BGP-LS routing table information\n'
        f'Router identifier {input["router_id"]}, local AS number {input["asn"]}\n'
        f'Status codes: * valid, > best, + inserted\n'
        f'Origin codes: i - IGP, e - EGP, ? - incomplete\n'
        f'Prefix codes: E link, V node, T IP reacheable route, S SRv6 SID, SP SRTE Policy, u/U unknown,\n'
        f'          I Identifier, N local node, R remote node, L link, P prefix, S SID,\n'
        f'          L1/L2 ISIS level-1/level-2, O OSPF, D direct, S static/peer-node,\n'
        f'          a area-ID, l link-ID, t topology-ID, s ISO-ID,\n'
        f'          c confed-ID/ASN, b bgp-identifier, r router-ID, s SID,\n'
        f'          i if-address, n nbr-address, o OSPF Route-type, p IP-prefix,\n'
        f'          d designated router address\n'
        f'\n'
        f'{"Network":>17} {"Next Hop":>24} {"Metric":>20} {"LocPref":>14} {"Weigth":>7} {"Path":>6}\n'
    )
    PREFIX_CODES = ["E", "V", "T", "S"]

    ORIGINS = {
        "igp": "i",
        "egp": "e",
        "incomplete": "?"
    }
    
    for route in input["bgp_routes"]:
        route_string = ""
        for k in route.keys():
            # first print the actual LS NLRI
            if k[1] in PREFIX_CODES:
                route_string += f'       {k}\n'
        # first print best path, then the rest
        for path in route["paths"]:
            if path["best"]:
                as_seq = " ".join(map(str,path["as_path"]["as_sequence"]))
                if len(path["as_path"]["as_set"]) == 0:
                    as_set = ""
                else:
                    as_set = "{" + ",".join(map(str,path["as_path"]["as_set"])) + "}"
                if path["inserted"]:
                    route_string += f'*>+ {path["next_hop"]:>39} {str(path.get("multi_exit_disc", 0)):>20} {str(path["local_pref"]):>14} {str(path["weight"]):>7}   {as_seq} {as_set} {ORIGINS[path["origin"]]}\n'
                else:
                    route_string += f'*>  {path["next_hop"]:>39} {str(path.get("multi_exit_disc", 0)):>20} {str(path["local_pref"]):>14} {str(path["weight"]):>7}   {as_seq} {as_set} {ORIGINS[path["origin"]]}\n'
        for path in route["paths"]:
            if not path["best"]:
                as_seq = " ".join(map(str,path["as_path"]["as_sequence"]))
                if len(path["as_path"]["as_set"]) == 0:
                    as_set = ""
                else:
                    as_set = "{" + ",".join(map(str,path["as_path"]["as_set"])) + "}"
                route_string += f'{path["next_hop"]:>42} {str(path.get("multi_exit_disc", 0)):>20} {str(path["local_pref"]):>14} {str(path["weight"]):>7}   {as_seq} {as_set} {ORIGINS[path["origin"]]}\n'

        output += route_string


    return output[:-1]


# for print_show_bgp_link_state_detail
def format_ls_attributes(ls_attributes):
    LS_ATTRIBUTES_FORMATTING = {
        "lsattr_local_link_id": "Link ID: Local:",
        "lsattr_remote_link_id": "Remote:",
        "multi_topology_id": "MT-ID:",
        "msd_type": "MSD Type:",
        "msd": "MSD:",
        "node_flags": "Node flags:",
        "node_name": "Node name:",
        "isis_area_id": "ISIS area ID:",
        "ipv4_local_router_id": "Local TE IPv4 Router-ID:",
        "ipv4_remote_router_id": "Remote TE IPv4 Router-ID:",
        "ipv6_local_router_id": "Local TE IPv6 Router-ID:",
        "ipv6_remote_router_id": "Remote TE IPv6 Router-ID:",
        "srgb_base": "SRGB Base:",
        "srgb_range": "Range:",
        "sr_capability_flags": "SR Capability Flags:",
        "sr_algorithm": "SR Algorithm:",
        "srlb_base": "SRLB Base:",
        "srlb_range": "Range:", 
        "admin_group": "Admin-group:",
        "extended_admin_group": "Ext-admin-group:",
        "max_link_bandwidth": "Max-link-bw:",
        "max_reservable_bandwidth": "Max-reservable-bw:",
        "unreserved_bandwidth": "Unreserved-bw:",
        "te_default_metric": "TE default metric:",
        "igp_metric": "IGP metric:",
        "srlg": "SRLG:",
        "adj_sids": "ADJ-SID:",
        "lan_adj_sids": "LAN-ADJ_SID:",
        "peer_sids": "Peer-SID:",
        "igp_flags": "IGP flags:",
        "igp_prefix_metric": "IGP prefix metric:",
        "algorithm": "Algorithm:",
        "prefix_sid": "Prefix-SID:",
        # those flags are not very important and make output look ugly
        #"prefix_attribute_flags": "Prefix attribute flags:",
        "source_router_identifier": "Source router ID",
        "bandwidth_rate_bps": "SRTE Bandwidth rate bps"
    }

    def format_adj_sids(adj_sids):
        output = ""
        for adj_sid in adj_sids:
            output += f'{str(adj_sid["adj_sid"])}, '
        return output
    
    def format_lan_adj_sids(lan_adj_sids):
        output = ""
        for adj_sid in lan_adj_sids:
            output += f'{str(adj_sid["lan_adj_sid"])} Nbr {adj_sid["neighbor_router_id"]}, '
        return output
    
    def format_prefix_sid(prefix_sid):
        return f'{str(prefix_sid["prefix_sid"])}, '
    
    def format_peer_sids(peer_sids):
        output = ""
        for peer_sid in peer_sids:
            output += f'{str(peer_sid["peer_sid"])}, '
        return output        
    
    LS_ATTRIBUTES_FANCY_FORMATTING = {
        "adj_sids": format_adj_sids,
        "lan_adj_sids": format_lan_adj_sids,
        "prefix_sid": format_prefix_sid,
        "peer_sids": format_peer_sids
    }

    output = ""
    current_output_line = f'      Link-state: '
    for k, v in LS_ATTRIBUTES_FORMATTING.items():
        if k not in ls_attributes.keys(): continue
        if k in LS_ATTRIBUTES_FANCY_FORMATTING:
            func = LS_ATTRIBUTES_FANCY_FORMATTING[k]
            formatted_output = func(ls_attributes[k])
            new_attribute = f'{v} {formatted_output}'
        else:
            new_attribute = f'{v} {str(ls_attributes[k])}, '
        if len(current_output_line + new_attribute) > 80:
            current_output_line += '\n'
            output += current_output_line
            current_output_line = f'                  '
        current_output_line += new_attribute

    output += f'{current_output_line[:-2]}\n'
    return output



def print_show_bgp_link_state_detail(input):
    output = (
        f'BGP-LS routing table information\n'
        f'Router identifier {input["router_id"]}, local AS number {input["asn"]}\n'
        f'Prefix codes: E link, V node, T IP reacheable route, S SRv6 SID, SP SRTE Policy, u/U unknown,\n'
        f'          I Identifier, N local node, R remote node, L link, P prefix, S SID,\n'
        f'          L1/L2 ISIS level-1/level-2, O OSPF, D direct, S static/peer-node,\n'
        f'          a area-ID, l link-ID, t topology-ID, s ISO-ID,\n'
        f'          c confed-ID/ASN, b bgp-identifier, r router-ID, s SID,\n'
        f'          i if-address, n nbr-address, o OSPF Route-type, p IP-prefix,\n'
        f'          d designated router address\n'
        f'\n'
    )
    PREFIX_CODES = ["E", "V", "T", "S"]


    PROTOCOL_IDS = {
        BgpAttribute.BgpLsNlri.ISIS_LEVEL1: "ISIS L1",
        BgpAttribute.BgpLsNlri.ISIS_LEVEL2: "ISIS L2",
        BgpAttribute.BgpLsNlri.OSPFV2: "OSPFv2",
        BgpAttribute.BgpLsNlri.DIRECT: "DIRECT",
        BgpAttribute.BgpLsNlri.STATIC: "STATIC",
        BgpAttribute.BgpLsNlri.OSPFV3: "OSPFv3",
        BgpAttribute.BgpLsNlri.BGP: "BGP"
    }    
    
    for route in input["bgp_routes"]:
        route_string = ""
        for k in route.keys():
            # first print the actual LS NLRI
            if k[1] in PREFIX_CODES:
                route_string += f'BGP routing table entry for {k}\n'
                route_details = route[k]
        route_string += f'NLRI Type: {route_details["type"]}\n'
        route_string += f'Protocol: {PROTOCOL_IDS.get(route_details["protocol_id"], None)}\n'
        route_string += f'Identifier: {route_details.get("identifier", 0)}\n'
        route_string += f'Local Node Descriptor:\n'
        route_string += f'      AS Number: {route_details["autonomous_system"]}\n'
        route_string += f'      BGP Identifier: {route_details.get("bgp_ls_id", "0.0.0.0")}\n'
        if route_details["protocol_id"] == BgpAttribute.BgpLsNlri.ISIS_LEVEL1 or route_details["protocol_id"] == BgpAttribute.BgpLsNlri.ISIS_LEVEL2:
            route_string += f'      ISO Node ID: {route_details["igp_router_id"]}\n'
        elif route_details["protocol_id"] == BgpAttribute.BgpLsNlri.BGP:
            route_string += f'      BGP Router Identifier: {route_details["bgp_router_id"]}\n'
        elif route_details["protocol_id"] == BgpAttribute.BgpLsNlri.OSPFV2:
            route_string += f'      Area ID: {route_details["ospf_area_id"]}\n'
            route_string += f'      Router ID IPv4: {route_details["igp_router_id"]}\n'
            ospf_dr_address = route_details.get("ospf_dr_address", None)
            if ospf_dr_address:
                route_string += f'      Designated Router Address: {ospf_dr_address}\n'
        elif route_details["protocol_id"] == BgpAttribute.BgpLsNlri.SR:
            route_string += f'      BGP Router Identifier: {route_details["bgp_router_id"]}\n'
            route_string += f'      TE Router Identifier: {route_details["igp_router_id"]}\n'
            route_string += f'SRTE Policy CP Descriptor:\n'
            route_string += f'      Protocol origin: SR Policy\n'
            flags = route_details.get("flags", 0)
            route_string += f'      Flags: {flags}\n'
            route_string += f'      Endpoint: {route_details["sr_policy_endpoint"]}\n'
            route_string += f'      Color: {route_details["sr_policy_color"]}\n'
            route_string += f'      AS Number: {route_details["autonomous_system"]}\n'
            route_string += f'      Originator Address: {route_details["igp_router_id"]}\n'
            route_string += f'      Discriminator: 100\n'
        if route_details["type"] == "link":
            route_string += f'Remote Node Descriptor:\n'
            route_string += f'      AS Number: {route_details["remote_autonomous_system"]}\n'
            route_string += f'      BGP Identifier: {route_details.get("remote_bgp_ls_id", "0.0.0.0")}\n'
            if route_details["protocol_id"] == BgpAttribute.BgpLsNlri.ISIS_LEVEL1 or route_details["protocol_id"] == BgpAttribute.BgpLsNlri.ISIS_LEVEL2:
                route_string += f'      ISO Node ID: {route_details["remote_igp_router_id"]}\n'
            elif route_details["protocol_id"] == BgpAttribute.BgpLsNlri.BGP:
                route_string += f'      BGP Router Identifier: {route_details["remote_bgp_router_id"]}\n'
            elif route_details["protocol_id"] == BgpAttribute.BgpLsNlri.OSPFV2:
                route_string += f'      Area ID: {route_details["remote_ospf_area_id"]}\n'
                route_string += f'      Router ID IPv4: {route_details["remote_igp_router_id"]}\n'
                ospf_dr_address = route_details.get("remote_ospf_dr_address", None)
                if ospf_dr_address:
                    route_string += f'      Designated Router Address: {ospf_dr_address}\n'
            route_string += f'Link Descriptor:\n'
            ipv4_interface_address = route_details.get("ipv4_interface_address", None)
            if ipv4_interface_address:
                route_string += f'      Local Interface Address IPv4: {ipv4_interface_address}\n'
            ipv4_neighbor_address = route_details.get("ipv4_neighbor_address", None)
            if ipv4_neighbor_address:
                route_string += f'      Neighbor Interface Address IPv4: {ipv4_neighbor_address}\n'
            ipv6_interface_address = route_details.get("ipv6_interface_address", None)
            if ipv6_interface_address:
                route_string += f'      Local Interface Address IPv6: {ipv6_interface_address}\n'
            ipv6_neighbor_address = route_details.get("ipv6_neighbor_address", None)
            if ipv6_neighbor_address:
                route_string += f'      Neighbor Interface Address IPv6: {ipv6_neighbor_address}\n'
            local_link_id = route_details.get("local_link_id", None)
            remote_link_id = route_details.get("remote_link_id", None)
            if local_link_id and remote_link_id:
                route_string += f'      Link ID: {local_link_id}.{remote_link_id}\n'          
            multi_topology_id = route_details.get("multi_topology_id", None)
            if multi_topology_id:
                route_string += f'      Multi-Topology: {multi_topology_id}\n'   
        if route_details["type"] == "ipv4_prefix" or route_details["type"] == "ipv6_prefix":
            route_string += f'Prefix Descriptor:\n'
            ospf_route_type = route_details.get("ospf_route_type", None)
            if ospf_route_type:
                route_string += f'      OSPF Route Type: {ospf_route_type}\n'
            multi_topology_id = route_details.get("multi_topology_id", None)
            if multi_topology_id:
                route_string += f'      Multi-Topology: {multi_topology_id}\n'   
            route_string += f'      Prefix: {route_details["prefix"]}\n'
        

        # best path is always printed first
        route_string += f'Paths: {len(route["paths"])} available, best #1\n'
        for path in route["paths"]:
            if path["best"]:
                if path["last_modified"]:
                    route_string += f'  Last modified: {datetime.fromtimestamp(int(path["last_modified"])).strftime("%B %d, %Y %H:%M:%S")}\n'
                local = True
                if len(path["as_path"]["as_sequence"]) > 0: 
                    local = False
                as_seq = " ".join(map(str,path["as_path"]["as_sequence"]))
                if len(path["as_path"]["as_set"]) == 0:
                    as_set = ""
                else:
                    as_set = "{" + ",".join(map(str,path["as_path"]["as_set"])) + "}"
                if local:
                    route_string += f'  Local\n'
                else:
                    route_string += f'  {as_seq} {as_set}\n'
                route_string += f'    {path["next_hop"]} from {path["peer_entry"]["remote_ip"]} ({path["peer_entry"]["remote_router_id"]})\n'
                route_string += f'      Origin {path["origin"]}, metric {path.get("multi_exit_disc", 0)}, localpref {path["local_pref"]}, weight {path["weight"]}, valid, {path["peer_entry"]["link_type"]}, best\n'
                originator_id = path.get("originator_id", None)
                if originator_id:
                    route_string += f'      Originator: {originator_id}, Cluster list: {path.get("cluster_list", [])}\n'
                ls_attributes = path.get("bgp_ls_attributes", None)
                if ls_attributes:
                    route_string += format_ls_attributes(ls_attributes)


        for path in route["paths"]:
            if not path["best"]:
                if path["last_modified"]:
                    route_string += f'  Last modified: {datetime.fromtimestamp(int(path["last_modified"])).strftime("%B %d, %Y %H:%M:%S")}\n'
                local = True
                if len(path["as_path"]["as_sequence"]) > 0: 
                    local = False
                as_seq = " ".join(map(str,path["as_path"]["as_sequence"]))
                if len(path["as_path"]["as_set"]) == 0:
                    as_set = ""
                else:
                    as_set = "{" + ",".join(map(str,path["as_path"]["as_set"])) + "}"
                if local:
                    route_string += f'  Local\n'
                else:
                    route_string += f'  {as_seq} {as_set}\n'
                route_string += f'    {path["next_hop"]} from {path["peer_entry"]["remote_ip"]} ({path["peer_entry"]["remote_router_id"]})\n'
                route_string += f'      Origin {path["origin"]}, metric {path.get("multi_exit_disc", 0)}, localpref {path["local_pref"]}, weight {path["weight"]}, valid, {path["peer_entry"]["link_type"]}, not best reason: {path.get("reason_not_best", None)}\n'
                originator_id = path.get("originator_id", None)
                if originator_id:
                    route_string += f'      Originator: {originator_id}, Cluster list: {path.get("cluster_list", [])}\n'
                ls_attributes = path.get("bgp_ls_attributes", None)
                if ls_attributes:
                    route_string += format_ls_attributes(ls_attributes)
        route_string += '\n'

        output += route_string

    
    return output[:-1]




def print_bgp_internal(input):
    output = (
        f'BGP internal information\n'
        f'  BGP server running: {str(input["running"])}\n'
        f'  Greenthreads available: {str(input["greenthreads_available"])}\n'
        f'  Config changes queued: {str(input["config_changes_queued_count"])}\n'
        f'\n'
        f'  Running sessions count: {str(input["running_sessions_count"])}\n'
        f'  Running sessions: {str(input["running_sessions"])}\n'
        f'\n'
        f'  Running ribs count: {str(input["running_ribs_count"])}\n'
        f'  Running ribs: {str(input["running_ribs"])}\n'
        f'\n'
        f'  Loc-Rib status per AF:\n'
        f'\n'
        f'{"Rib size":>40} {"Rib update queue size":>30}\n'
        f'    Link-State: {str(input["link_state"]["rib_size"]):>24} {str(input["link_state"]["update_route_queue_size"]):>30}\n'
    )

    return output[:-1]


def print_show_management_api_http(input):

    output = (
        f'HTTP server statistics\n'
        f'\n'
        f'{"Enabled:":20} {str(input["enabled"])}\n'
        f'{"Running:":20} {str(input["running"])}\n'
        f'{"Port:":20} {str(input["port"])}\n'
        f'{"Hit count:":20} {str(input["hit_count"])}\n'
        f'{"Last hit:":20} {datetime.fromtimestamp(input["last_hit"]).strftime("%B %d, %Y %H:%M:%S")}\n'
    )

    return output[:-1]


def print_show_management_api_https(input):

    output = (
        f'HTTP server statistics\n'
        f'\n'
        f'{"Enabled:":20} {str(input["enabled"])}\n'
        f'{"Running:":20} {str(input["running"])}\n'
        f'{"Port:":20} {str(input["port"])}\n'
        f'{"Hit count:":20} {str(input["hit_count"])}\n'
        f'{"Last hit:":20} {datetime.fromtimestamp(input["last_hit"]).strftime("%B %d, %Y %H:%M:%S")}\n'
        f'{"Certificate:":20} {str(input["certificate"])}\n'
        f'{"Key:":20} {str(input["key"])}\n'
        f'{"Ciphers:":20} {str(input["ciphers"])}\n'
        f'{"TLS versions:":20} {str(input["tls_version"])}\n'
    )

    return output[:-1]


def print_show_management_syslog(input):

    output = (
        f'Configured syslog hosts\n'
        f'\n'
        f'  {"Host":<30} {"Port":<20} {"Protocol":<20} {"Active":<20}\n'
        f'  {"----":<30} {"----":<20} {"--------":<20} {"------":<20}\n'
    )
    for host in input["configured_syslog_hosts"]:
        output += f'  {host["remote_ip"]:<30} {str(host["port"]):<20} {str(host["protocol"]):<20} {str(host["active"]):<20}\n'

    return output[:-1]


def print_show_sampling_summary(input):
    output = ( 
        f'Sampling summary information\n'
        f'\n' 
        f'    {"Sampling interval":40} {input["sampling_interval"]}\n'
        f'    {"Adjust interval:":40} {input["adjust_interval"]}\n'
        f'    {"Actual adjust interval:":40} {input["actual_adjust_interval"]}\n'
        f'    {"Adjust threshold:":40} {input["adjust_threshold"]}\n'
        f'    {"Last adjusted:":40} {input["last_adjusted"]}\n'
        f'    {"Sampling DB path:":40} {input["sampling_database_path"]}\n'
        f'\n'
        f'  {"Sampler":20} {"Valid config":>10} {"Running":>10} {"OS":>10} {"Auth":>15} {"Last read time":>20}\n'
    )

    for sampler in input["samplers"].keys():
        sampler_ip = sampler
        valid_config = str(input["samplers"][sampler]["valid_config"])
        running = str(input["samplers"][sampler]["running"])
        os = str(input["samplers"][sampler]["os"])
        auth = str(input["samplers"][sampler]["auth"])
        last_read_time = input["samplers"][sampler]["last_read_time"]
        if not last_read_time: 
            last_read_time = "Never"
        last_read_time = str(last_read_time)
        if "day" in last_read_time:
            # then print <days>d<hours>h
            num_days = last_read_time.split()[0]
            num_hours = last_read_time.split()[2].split(":")[0]
            last_read_time = f'{num_days}d{num_hours}h'

        sampler_string = f'  {sampler_ip:20} {valid_config:>12} {running:>10} {os:>10} {auth:>15} {last_read_time:>20}\n'
        output += sampler_string

    return output[:-1]



def print_show_sampling_clients(input):
    output = ""
    for sampler in input["sampler_list"]:

        if sampler["valid_config"]:
            config_status = "Valid config"
        else:
            config_status = "Invalid config, reason " + sampler ["invalid_config_reason"]

        if sampler["running"]:
            running_status = "Sampler is running"
        else:
            running_status = "Sampler is not running"

        sampler_string = (
            f'Sampling client is {sampler["sampler_ip"]}, port {sampler["port"]}\n'
            f'  {config_status}\n'
            f'  {running_status}\n'
            f'  Last read {sampler["last_read_time"]}\n'
            f'  Sampling interval is {str(sampler["sampling_interval"])} seconds\n'
            f'  Remote router-id is {sampler["router_id"]}\n'
            f'  Remote OS is {sampler["os"]}, auth {sampler["auth"]}\n'
        )

        output += sampler_string

    return output[:-1]


def format_bps(rate_bps, decimals=3, width=7):
    """
    Convert bits-per-second into a human-readable string.

    Args:
        rate_bps (int|float): rate in bits per second
        decimals (int): number of decimal places

    Returns:
        str: formatted rate, e.g. "41.822 Gbps"
    """

    if rate_bps is None:
        return "0 bps"

    rate = float(rate_bps)

    units = [
        ("Tbps", 1_000_000_000_000),
        ("Gbps", 1_000_000_000),
        ("Mbps", 1_000_000),
        ("Kbps", 1_000),
        ("bps", 1),
    ]

    for unit, factor in units:
        if rate >= factor:
            value = rate / factor
            if unit == "bps":
                return f"{int(value):>{width}} {unit}"
            return f"{value:>{width}.{decimals}f} {unit}"

    return "0 bps"


def print_show_sampling_policies(input):

    total_num_policies = len(input["policies_list"])
    num_stale_policies = 0
    for policy in input["policies_list"]:
        if policy["stale"]:
            num_stale_policies += 1
    num_active_policies = total_num_policies - num_stale_policies
    output = (
        f'Sampling policies information\n'
        f'Number of policies: {total_num_policies}, active {num_active_policies}, stale {num_stale_policies} \n'
        f'Status codes: ~ stale\n'
        f'\n'
        f'    {"Policy":40} {"Rate":>20} {"Last updated":>30}\n'
    )
    
    for policy in input["policies_list"]:
        status = "   "
        if policy["stale"]:
            status = " ~ "
        policy_key = f'[{policy["router_id"]}][{policy["endpoint"]}][{policy["color"]}]'
        last_updated = policy["last_updated"]
        last_updated = str(timedelta(seconds=int(time()) - last_updated))
        if not last_updated: 
            last_updated = "Never"
        last_updated = str(last_updated)
        if "day" in last_updated:
            # then print <days>d<hours>h
            num_days = last_updated.split()[0]
            num_hours = last_updated.split()[2].split(":")[0]
            last_updated = f'{num_days}d{num_hours}h'
        policy_string = f'{status} {policy_key:40} {format_bps(policy["rate_bps"]):>20} {last_updated:>30}\n'

        output += policy_string

    return output[:-1]


def print_show_sampling_policies_detail(input):

    total_num_policies = len(input["policies_list"])
    num_stale_policies = 0
    for policy in input["policies_list"]:
        if policy["stale"]:
            num_stale_policies += 1
    num_active_policies = total_num_policies - num_stale_policies
    output = (
        f'Detailed sampling policies information\n'
        f'Number of policies: {total_num_policies}, active {num_active_policies}, stale {num_stale_policies} \n'
        f'\n'
    )
    
    for policy in input["policies_list"]:
        policy_key = f'[{policy["router_id"]}][{policy["endpoint"]}][{policy["color"]}]'
        policy_string = f'Sampled policy entry for {policy_key}\n'
        policy_string += f'  Router-id: {policy["router_id"]}\n'
        policy_string += f'  Endpoint: {policy["endpoint"]}\n'
        policy_string += f'  Color: {policy["color"]}\n'
        policy_string += f'  Rate {format_bps(policy["rate_bps"])}, calculated from {str(policy["samples"])} samples within {str(policy["window_seconds"])} seconds\n'
        last_updated = policy["last_updated"]
        last_updated = str(timedelta(seconds=int(time()) - last_updated))
        if not last_updated: 
            last_updated = "Never"
        last_updated = str(last_updated)
        policy_string += f'  Last updated: {last_updated} ago\n'
        if policy["stale"]:
            policy_string += f'  *Warning: policy is stale, will be deleted soon if no update received\n'
        output += policy_string

    return output[:-1]


def print_sampling_internal(input):
    output = (
        f'Sampling internal information\n'
        f'  Sampling server running: {str(input["running"])}\n'
        f'  Greenthreads available: {str(input["greenthreads_available"])}\n'
        f'  Config changes queued: {str(input["config_changes_queued_count"])}\n'
        f'\n'
        f'  Running samplers count: {str(input["running_samplers_count"])}\n'
        f'  Running samplers: {str(input["running_samplers"])}\n'
        f'\n'
        f'  GNMI streaming queue size: {str(input["gnmi_streaming_queue_size"])}\n'
        f'  Sampling to BGP queue size: {str(input["sampling_to_bgp_queue"])}\n'
        f'  Sampled policies number {str(input["sampled_policies_number"])}\n'
    )

    return output[:-1]