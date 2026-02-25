#!/usr/bin/env python3

from pprint import pprint
from eventlet import GreenPool, listen, connect, greenthread, sleep, semaphore
from eventlet.green import socket
from eventlet.queue import Queue
from time import time
import struct
import copy

from .bgp_defaults import *
from .bgp_message import *


class BgpSession:
    def __init__(self, neighbor):
        self.neighbor = neighbor
        self.fsm = neighbor.fsm
        self.counters = neighbor.counters
        self.conn = None
        self.input = None
        self.neighbor_address = neighbor.remote_ip
        self.neighbor_port = BGP_TCP_PORT
        self.ttl = 1
        self.eventlets = []
        self.pool = GreenPool()
        self.admin_down = False
        self.pfx_limit_exceeded = False
        self.idle_hold_extended = False
        if not self.neighbor.remote_as:
            self.admin_down = True
        self.running = False
        self.connecting = False
        if neighbor.link_type == "internal":
            self.ttl = 255
        if neighbor.link_type == "external" and neighbor.ebgp_multihop:
            self.ttl = neighbor.ebgp_multihop


    def run(self):
        self.admin_down = False
        self.pfx_limit_exceeded = False
        self.running = True
        self.eventlets.append(self.pool.spawn(self.read_input_buffer))
        self.eventlets.append(self.pool.spawn(self.receive_messages))
        self.eventlets.append(self.pool.spawn(self.send_messages))
        self.eventlets.append(self.pool.spawn(self.check_timers))
        self.eventlets.append(self.pool.spawn(self.initiate_connection))
        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Started BGP session')
        self.exit_idle()
        self.pool.waitall()

    def stop_session(self, deconfigured=False, pfx_limit=False):
        self.admin_down = True
        if pfx_limit:
            self.pfx_limit_exceeded = True
        self.neighbor.logger.info(f'Bgp neighbor {self.neighbor_address}: Old state {self.fsm.state} new state Idle')
        self.fsm.state = "Idle"
        if deconfigured:
            self.drop_session(BgpNotification.CEASE, BgpNotification.PEER_DECONFIGURED)
        else:
            self.drop_session(BgpNotification.CEASE, BgpNotification.ADMIN_SHUTDOWN)
        for eventlet in self.eventlets:
            eventlet.kill()
        self.eventlets = []
        self.running = False
        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Stopped BGP session')

    def reset_session(self):
        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Resetting BGP session')
        self.drop_session(BgpNotification.CEASE, BgpNotification.ADMIN_RESET)
        if self.neighbor.bgp_server.ls_loc_rib.update_route_queue.qsize() > 50000 or self.neighbor.bgp_server.ipv4_lu_loc_rib.update_route_queue.qsize() > 50000 or self.neighbor.bgp_server.ipv6_lu_loc_rib.update_route_queue.qsize() > 50000:
            self.idle_hold_extended = True
            self.neighbor.logger.warning(f'Bgp neighbor {self.neighbor_address}: Extending idle hold time because RIB update queue has over 50k routes. Will attempt to bring neighbor up once the update queue clears')
        else:
            self.exit_idle()

    def exit_idle(self):
        self.idle_hold_extended = False
        self.fsm.last_idle_hold_timer = int(time())
        if self.neighbor.passive:
            self.fsm.last_state = self.fsm.state
            self.fsm.state = "Active"
            self.neighbor.logger.info(f'Bgp neighbor {self.neighbor_address}: Old state Idle new state Active')
        else:
            self.fsm.last_state = self.fsm.state
            self.fsm.state = "Connect"
            self.neighbor.logger.info(f'Bgp neighbor {self.neighbor_address}: Old state Idle new state Connect')
            self.connecting = False
        

    def initiate_connection(self):
        while True:
            sleep(0.1)
            if self.fsm.state != "Connect": continue
            if self.connecting: continue
            #self.fsm.last_state = self.fsm.state
            #self.fsm.state = "Active"
            self.fsm.last_connect_retry_timer = int(time())
            self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Resolving local IP')
            self.neighbor.update_local_ip()
            self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Local IP is {self.neighbor.local_ip}')
            if not self.neighbor.local_ip: continue
            self.connecting = True
            try:
                if ":" in self.neighbor_address:
                    self.conn2 = connect((self.neighbor_address, self.neighbor_port), socket.AF_INET6)
                else:
                    self.conn2 = connect((self.neighbor_address, self.neighbor_port), socket.AF_INET)
                if not self.conn:
                    self.accept_connection(self.conn2, (self.neighbor_address, self.neighbor_port))
            except Exception as e:
                self.neighbor.logger.warning(f'Bgp neighbor {self.neighbor_address}: Unable to connect to BGP neighbor {self.neighbor_address}, exception {e.__class__.__name__, e.args}')
                self.connecting = False
                if self.fsm.state != "Established":
                    self.fsm.last_state = self.fsm.state
                    self.neighbor.logger.info(f'Bgp neighbor {self.neighbor_address}: Old state {self.fsm.state} new state Active')
                    self.fsm.state = "Active"

    
    def accept_connection(self, conn, address):
        sleep(0.1)            
        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Accepting connection')
        self.conn = conn
        #print("accepted connection")
        self.conn.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)
        self.neighbor_address = address[0]
        self.neighbor_port = address[1]
        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Creating socket file')
        self.input = self.conn.makefile(mode="rb")
        self.neighbor.update_local_ip()
        if self.fsm.state == "Idle":
            self.drop_session(BgpNotification.CEASE, BgpNotification.CONNECTION_REJECTED)
            


    def drop_session(self, error_code=None, error_subcode=None):
        if error_code and self.conn:            
            message = BgpNotification(error_code, error_subcode)
            message_length = BgpMessage.HEADER_LENGTH + len(message.generate())
            header = struct.pack("!16sHB", BgpMessage.MARKER, message_length, message.MESSAGE_TYPE)
            self.counters.increment_out_msg_stats(message.MESSAGE_TYPE)
            self.counters.update_last_sent()
            try:
                self.conn.send(header + message.generate())
                self.neighbor.logger.info(f'Bgp neighbor {self.neighbor_address}: Sent Notification, code {BgpNotification.get_error_code(error_code)} / subcode {BgpNotification.get_error_subcode(error_code, error_subcode)}')
            except Exception as e:
                self.neighbor.logger.warning(f'Bgp neighbor {self.neighbor_address}: Failed to send Notification code {BgpNotification.get_error_code(error_code)} / subcode {BgpNotification.get_error_subcode(error_code, error_subcode)} - exception {e.__class__.__name__, e.args}')
        self.neighbor.logger.info(f'Bgp neighbor {self.neighbor_address}: Old state {self.fsm.state} new state Idle')
        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Deleting all Rib-in routes')
        for rib_in in self.neighbor.RIB_INS.values():
            if not rib_in: continue
            rib_in.del_all_routes()
        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Deleting all Rib-out routes')
        for rib_out in self.neighbor.RIB_OUTS.values():
            if not rib_out: continue
            rib_out.reset_rib()
        if self.fsm.state == "Established":
            self.fsm.last_down = int(time())
        self.fsm.last_state = self.fsm.state
        self.fsm.state = "Idle"
        self.fsm.last_hold_timer = int(time())
        if self.fsm.last_state != "Idle":
            self.fsm.last_idle_hold_timer = int(time())
        self.fsm.negotiated_capabilities = []
        self.fsm.output_queue = Queue()
        self.fsm.input_queue = Queue()
        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Closing input')
        try:
            # closing self.input can cause this function to hang if there are messages left e.g. when firewall is blocking traffic
            # leaving self.input to be cleaned by gc
            #if self.input:
            #    self.input.close()
            self.input = None
            if self.conn:
                self.conn.shutdown(socket.SHUT_RDWR)
                self.conn.close()
                self.conn = None
        except Exception as e:
            self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Failed to properly close input for BGP session - exception {e.__class__.__name__, e.args}')
            self.input = None
            self.conn = None
        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Closed connection')


    def read_input_buffer(self):
        while True:
            sleep(0.01)
            if not self.conn: continue
            if self.fsm.state == "Idle": continue
            if not self.input: continue
            init_time = round(time()*1000)
            incomplete_message_data = b""
            #self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Reading input buffer...')
            while True:
                #if round(time()*1000) - init_time > 500: break
                if not self.input: break
                try:
                    if len(incomplete_message_data) > 0:
                        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Reading incomplete data from previous message...')
                        while len(incomplete_message_data) != data_length:
                            message_data = self.input.read(data_length - len(incomplete_message_data))
                            if not message_data: continue
                            incomplete_message_data += message_data
                        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Put message type {BgpMessage.get_message_type(message_type)} in input Q')
                        self.fsm.input_queue.put((message_type, incomplete_message_data))
                        break
                except Exception as e:
                    self.neighbor.logger.warning(f'Bgp neighbor {self.neighbor_address}: Failed to finish reading incomplete BGP input - exception {e.__class__.__name__, e.args}')

                # moved timeout break here to see if it fixes bad marker issue with XR
                if round(time()*1000) - init_time > 500: break
                
                try:
                    #self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Reading new header...')
                    header = self.input.read(BgpMessage.HEADER_LENGTH)   
                except Exception as e:
                    self.neighbor.logger.warning(f'Bgp neighbor {self.neighbor_address}: Failed to read BGP input - exception {e.__class__.__name__, e.args}')
                    break
                if not header: break

                incomplete_message_data = b""


                try:
                    marker, message_length, message_type = struct.unpack("!16sHB", header)
                except Exception as e:
                    self.neighbor.logger.warning(f'Bgp neighbor {self.neighbor_address}: Failed to parse BGP input - exception {e.__class__.__name__, e.args}')
                    break

                if marker != BgpMessage.MARKER:
                    self.neighbor.logger.error(f'Bgp neighbor {self.neighbor_address}: Recevied bad BGP marker {marker.hex(" ", 1)}')
                    self.drop_session(BgpNotification.MESSAGE_HEADER_ERROR, BgpNotification.BAD_MESSAGE_TYPE)
                    break
                if message_length < BgpMessage.HEADER_LENGTH:
                    self.drop_session(BgpNotification.MESSAGE_HEADER_ERROR, BgpNotification.BAD_MESSAGE_LENGTH)
                    break
                if message_length == BgpMessage.HEADER_LENGTH:
                    message_data = None
                else:
                    data_length = message_length - BgpMessage.HEADER_LENGTH
                    self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Reading new message...')
                    try:
                        message_data = self.input.read(data_length)
                        if len(message_data) != data_length:
                            #print(f'Received incorrect message length {len(message_data)}')
                            incomplete_message_data = message_data
                            continue
                    except Exception as e:
                        self.neighbor.logger.warning(f'Bgp neighbor {self.neighbor_address}: Failed to read BGP message_data - exception {e.__class__.__name__, e.args}')
                        break
                self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Put message type {BgpMessage.get_message_type(message_type)} in input Q')
                self.fsm.input_queue.put((message_type, message_data))
                


    def receive_messages(self):
        while True:
            sleep(0.01)
            if not self.conn: continue
            if not self.input: continue
            if self.fsm.state == "Idle": continue
            if not self.fsm.input_queue.qsize(): continue
            init_time = round(time()*1000)
            while self.fsm.input_queue.qsize():
                if round(time()*1000) - init_time > 200: break
                if self.fsm.input_queue.qsize():
                    self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Fetching message from input Q')
                    message_type, message_data = self.fsm.input_queue.get()
                    self.counters.increment_in_msg_stats(message_type)
                    self.counters.update_last_received()
                    try:
                        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Trying to parse BGP message type {BgpMessage.get_message_type(message_type)}')
                        message = BgpMessageParser(message_type, message_data).parse()
                        self.fsm.message_received(message_type, message)
                    except Exception as e:
                        self.neighbor.logger.error(f'Bgp neighbor {self.neighbor_address}: Failed to parse BGP message type {BgpMessage.get_message_type(message_type)} - exception {e.__class__.__name__, e.args}, message data {message_data.hex(" ", 1)}')


    def send_messages(self):
        while True:
            sleep(0.01)
            try:
                if not self.conn: continue
                if self.fsm.state == "Active" or self.fsm.state == "Connect":
                    self.neighbor.logger.info(f'Bgp neighbor {self.neighbor_address}: Old state {self.fsm.state} new state OpenSent')
                    self.fsm.last_state = self.fsm.state
                    self.fsm.state = "OpenSent"
                    if self.neighbor.local_as > 65535:
                        message = BgpOpen(4, 23456, self.fsm.hold_timer, self.fsm.neighbor.local_router_id, self.fsm.neighbor.capabilities)
                    else:
                        message = BgpOpen(4, self.fsm.neighbor.local_as, self.fsm.hold_timer, self.fsm.neighbor.local_router_id, self.fsm.neighbor.capabilities)
                    message_length = BgpMessage.HEADER_LENGTH + len(message.generate())
                    header = struct.pack("!16sHB", BgpMessage.MARKER, message_length, message.MESSAGE_TYPE)
                    self.counters.increment_out_msg_stats(message.MESSAGE_TYPE)
                    self.counters.update_last_sent()
                    try:
                        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Sending BGP Open')
                        self.conn.send(header + message.generate())
                    except Exception as e:
                        self.neighbor.logger.error(f'Bgp neighbor {self.neighbor_address}: Failed to send BGP Open - exception {e.__class__.__name__, e.args}')
                        self.neighbor.logger.info(f'Bgp neighbor {self.neighbor_address}: Old state {self.fsm.state} new state Idle')
                        self.fsm.last_state = self.fsm.state                     
                        self.fsm.state = "Idle"
                        self.conn = None
                        self.input = None
                if not self.fsm.output_queue.qsize(): continue
                self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Sending queued BGP messages...')
                max_message_size = self.return_session_mss()
                self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Returned MSS {max_message_size}')
                if not max_message_size:
                    max_message_size = 536
                if max_message_size > 4096:
                    max_message_size = 4096
                self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Max message size set to {max_message_size}')
                init_time = round(time()*1000)
                packed_messages = b""
                while self.fsm.output_queue.qsize():
                    if round(time()*1000) - init_time > 200:
                        # send whatever was packed so far before yielding thread
                        if len(packed_messages) > 0:
                            self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Sending packed messages before yielding thread...')
                            self.counters.update_last_sent()
                            self.conn.send(packed_messages)
                            packed_messages = b""
                        break
                    message = self.fsm.output_queue.get()
                    message_length = BgpMessage.HEADER_LENGTH + len(message.generate())
                    header = struct.pack("!16sHB", BgpMessage.MARKER, message_length, message.MESSAGE_TYPE)
                    self.counters.increment_out_msg_stats(message.MESSAGE_TYPE)
                    self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Fetched message type {BgpMessage.get_message_type(message.MESSAGE_TYPE)}')
                    message_bin = header + message.generate()
                    # if already packed enough messages to fill max message size, send an update
                    if len(packed_messages + message_bin) > max_message_size:
                        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Packed enough messages, sending a packet')
                        self.counters.update_last_sent()
                        self.conn.send(packed_messages)
                        packed_messages = message_bin
                    else:
                        packed_messages += message_bin
                    # if queue is empty now, send whatever was packed so far
                    if not self.fsm.output_queue.qsize():
                        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: No more messages in output Q, sending whatever packed so far')
                        self.counters.update_last_sent()
                        self.conn.send(packed_messages)
                        packed_messages = b""
            except Exception as e:
                self.neighbor.logger.error(f'Bgp neighbor {self.neighbor_address}: Failed to send BGP message - exception {e.__class__.__name__, e.args}')
                #msg = self.fsm.output_queue.get()
                #print(msg)
                #self.fsm.state = "Idle"
                


                

    def check_timers(self):
        while True:
            sleep(1)
            if self.fsm.state in self.fsm.KEEPALIVED_STATES:
                if int(time()) - self.fsm.last_hold_timer >= self.fsm.hold_timer:
                    self.neighbor.logger.warning(f'Bgp neighbor {self.neighbor_address}: Hold timer expired!')
                    self.drop_session(BgpNotification.HOLD_TIMER_EXPIRED, 0)
                if int(time()) - self.fsm.last_keepalive_timer >= self.fsm.keepalive_timer:
                    self.fsm.last_keepalive_timer = int(time())
                    self.fsm.output_queue.put(BgpKeepalive)
                    self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Sent Keepalive')
            if self.fsm.state == "Idle":
                if int(time()) - self.fsm.last_idle_hold_timer >= self.fsm.idle_hold_timer:
                    if self.neighbor.bgp_server.ls_loc_rib.update_route_queue.qsize() > 50000 or self.neighbor.bgp_server.ipv4_lu_loc_rib.update_route_queue.qsize() > 50000 or self.neighbor.bgp_server.ipv6_lu_loc_rib.update_route_queue.qsize() > 50000:
                        if not self.idle_hold_extended:
                            self.idle_hold_extended = True
                            self.neighbor.logger.warning(f'Bgp neighbor {self.neighbor_address}: Extending idle hold time because RIB update queue has over 50k routes. Will attempt to bring neighbor up once the update queue clears')
                        continue
                    self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Idle Hold timer expired, exiting Idle state')
                    self.exit_idle()
            if self.fsm.state == "Active" and not self.neighbor.passive:
                if int(time()) - self.fsm.last_connect_retry_timer >= self.fsm.connect_retry_timer:
                    self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Connect Retry timer expired, moving to Connect')
                    self.neighbor.logger.info(f'Bgp neighbor {self.neighbor_address}: Old state {self.fsm.state} new state Connect')
                    self.fsm.last_state = self.fsm.state
                    self.fsm.state = "Connect"
                    self.connecting = False


    def send_route_refresh(self):
        self.neighbor.logger.debug(f'Bgp neighbor {self.neighbor_address}: Sending Route Refresh')
        if BgpCapability.OTHER_CAPABILITIES['route-refresh'] in self.fsm.negotiated_capabilities:
            for af in BgpCapability.ADDRESS_FAMILIES.values():
                if af in self.fsm.negotiated_capabilities:
                    self.fsm.output_queue.put(BgpRouteRefresh(*af["value"]))

    def return_session_mss(self):
        if not self.conn: return
        return self.conn.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)



class BgpSessionCounters:
    def __init__(self, neighbor):
        self.neighbor = neighbor
        self.last_sent = int(time())
        self.last_received = int(time())
        self.IN_MSG_STATS = {
            "route_refreshes": 0,
            "notifications": 0,
            "updates": 0,
            "keepalives": 0,
            "opens": 0
        }
        self.OUT_MSG_STATS = {
            "route_refreshes": 0,
            "notifications": 0,
            "updates": 0,
            "keepalives": 0,
            "opens": 0
        }
    
    COUNTER_TYPES = {
        BgpMessage.OPEN: "opens",
        BgpMessage.UPDATE: "updates",
        BgpMessage.NOTIFICATION: "notifications",
        BgpMessage.KEEPALIVE: "keepalives",
        BgpMessage.ROUTE_REFRESH: "route_refreshes"
    }

    def update_last_sent(self):
        self.last_sent = int(time())

    def update_last_received(self):
        self.last_received = int(time())

    def increment_in_msg_stats(self, message_type):
        if message_type not in self.COUNTER_TYPES.keys():
            print(f"Invalid BGP message type {BgpMessage.get_message_type(message_type)}")
            return
        counter_type = self.COUNTER_TYPES[message_type]
        self.IN_MSG_STATS[counter_type] +=1

    def increment_out_msg_stats(self, message_type):
        if message_type not in self.COUNTER_TYPES.keys():
            print(f"Invalid BGP message type {BgpMessage.get_message_type(message_type)}")
            return
        counter_type = self.COUNTER_TYPES[message_type]
        self.OUT_MSG_STATS[counter_type] +=1       

    def return_in_msg_stats_summary(self):
        in_msg_stats_summary = 0
        for stat in self.IN_MSG_STATS:
            in_msg_stats_summary += self.IN_MSG_STATS[stat]
        return in_msg_stats_summary

    def return_out_msg_stats_summary(self):
        out_msg_stats_summary = 0
        for stat in self.OUT_MSG_STATS:
            out_msg_stats_summary += self.OUT_MSG_STATS[stat]
        return out_msg_stats_summary