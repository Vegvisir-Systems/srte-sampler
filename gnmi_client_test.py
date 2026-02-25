from pygnmi.client import gNMIclient
import json
import time
from queue import Queue, Empty
import threading
import re
from pprint import pprint
from time import time_ns
from datetime import datetime

def ns_to_datetime_str(ns: int) -> str:
    return datetime.fromtimestamp(ns / 1e9).strftime("%Y-%m-%d %H:%M:%S")


#start = time.perf_counter()
'''
cisco_router = {
    'target': '192.168.102.102',       # IOS XR router IP
    'port': 57400,               # default gNMI port
    'username': 'clab',
    'password': 'clab@123',
    'insecure': True             # set False if using valid TLS certs
}



# gNMI path to SR-TE policy counters
xr_ipv4_counters = [
    "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv4/state",
    "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv6/state"
]


xr_router_id = [
    "/network-instances/network-instance/protocols/protocol[identifier=BGP][name=default]/bgp/global/state/router-id"
]


SR_IF_RE = re.compile(
    r"interfaces/interface\[name=sr-srte_c_(?P<color>\d+)_ep_(?P<endpoint>[^\]]+)\]"
)

def extract_router_id(xr_reading):
    """
    xr_reading: dict returned by IOS-XR gNMI GET (json_ietf)
    returns: router-id string or None
    """

    for notif in xr_reading.get("notification", []):
        for upd in notif.get("update", []):
            path = upd.get("path", "")
            if path.endswith("/bgp/global/state/router-id"):
                return upd.get("val")

    return None


def parse_iosxr_sr_te_counters(data):
    """
    data: dict parsed from IOS-XR gNMI GET JSON output
    returns: list of dicts with IPv4 + IPv6 counters summed
    """

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
                    "timestamp": timestamp,
                    "color": color,
                    "endpoint": endpoint,
                    "out_octets": 0,
                }

            # IPv4 + IPv6 naturally summed here
            agg[key]["out_octets"] += out_octets

    return list(agg.values())


with gNMIclient(target=(cisco_router['target'], cisco_router['port']),
                username=cisco_router['username'],
                password=cisco_router['password'],
                insecure=cisco_router['insecure']) as client:

    # Perform gNMI GET
    ipv4_counter_reading = client.get(path=xr_ipv4_counters, encoding='json_ietf')
    #ipv4_counter_reading['notification'][0]['update'][6]['val']['counters']['out-octets'] = int(ipv4_counter_reading['notification'][0]['update'][6]['val']['counters']['out-octets']) + 2
    #ipv4_counter_reading['notification'][0]['update'][6]['val']['counters']['out-octets'] = int(ipv4_counter_reading['notification'][0]['update'][6]['val']['counters']['out-octets']) + 1
    #ipv6_counter_reading = client.get(path=xr_ipv6_counters, encoding='json_ietf')
    xr_router_id_reading = client.get(path=xr_router_id, encoding='json_ietf')
    parsed_counter_reading = parse_iosxr_sr_te_counters(ipv4_counter_reading)
    #parsed_ipv6_counter_reading = parse_iosxr_sr_te_counters(ipv6_counter_reading)
    router_id = extract_router_id(xr_router_id_reading)

    #for ipv4_entry in parsed_counter_reading:
    #    for ipv6_entry in parsed_ipv6_counter_reading:
    #        if ipv4_entry["color"] == ipv6_entry["color"] and ipv4_entry["endpoint"] == ipv6_entry["endpoint"]:
    #            ipv4_entry["out_octets"] += ipv6_entry["out_octets"]
                
    for entry in parsed_counter_reading:
        print(
            f"ts={entry['timestamp']} "
            f"color={entry['color']} "
            f"endpoint={entry['endpoint']} "
            f"out-octets={entry['out_octets']}"
        )

#print(json.dumps(result, indent=2))
#with open("gnmi_output.json", "w") as f:
#    json.dump(result, f, indent=2)
'''


# XR GNMI streaming
'''
subscription_request = {
    "subscription": [
        {
            "path": "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv4/state",
            "mode": "sample",
            "sample_interval": 10_000_000_000  # 10 seconds in nanoseconds
        }
    ],
    "mode": "stream"
}

with gNMIclient(target=("192.168.102.102", 57400),
                 username="clab", password="clab@123", insecure=True) as client:

    for update in client.subscribe(subscription_request):
        print(update)
'''
#end = time.perf_counter() 
#print(f"GET request took {end - start:.6f} seconds")

# JUNOS - streaming only 
#'''
juniper_router = {
    'target': '192.168.102.101', 
    'port': 32767,               # default gNMI port
    'username': 'admin',
    'password': 'admin@123',
    'insecure': True             # set False if using valid TLS certs
}

'''
def extract_router_id(resp):
    """
    resp: SubscribeResponse from pygnmi
    returns: router-id string or None
    """

    if not resp.HasField("update"):
        return None

    notif = resp.update

    for u in notif.update:
        elems = [e.name for e in u.path.elem]

        # Exact match
        if elems == ["bgp", "global", "state", "router-id"]:
            val = u.val.json_val

            # pygnmi may return str or bytes depending on version
            if isinstance(val, bytes):
                return val.decode().strip('"')
            else:
                return val.strip('"')

    return None


def extract_sr_te_policy_info(resp):
    """
    resp: SubscribeResponse object from pygnmi
    returns: dict or None
    """

    # Ignore non-update messages
    if not resp.HasField("update"):
        return None

    notif = resp.update

    result = {
        "timestamp": notif.timestamp,
        "to_address": None,
        "color": None,
        "bytes": None,
    }

    # Walk prefix to find sr-te-ip-policy keys
    for elem in notif.prefix.elem:
        if elem.name == "sr-te-ip-policy":
            result["to_address"] = elem.key.get("to-address")
            result["color"] = elem.key.get("color")

    for u in notif.update:
        if u.path.elem and u.path.elem[0].name == "bytes":
            result["bytes"] = int(u.val.json_val.decode())
    # Only return if we actually found policy identifiers
    if result["to_address"] is None or result["bytes"] is None:
        return None

    return result


subscription_request = {
    "subscription": [
        {
            "path": "/mpls/signaling-protocols/segment-routing/",
            "mode": "sample",
            "sample_interval": 10_000_000_000  # 10 seconds in nanoseconds
        }
    ],
    "mode": "stream",
}


def subscription_worker(client, subscription_request, queue):
    for update in client.subscribe(subscription_request):
        queue.put(update)

queue = Queue()
with gNMIclient(target=("192.168.102.101", 32767),
                 username="admin", password="admin@123", insecure=True) as client:
    print(f'Trigger time {ns_to_datetime_str(time_ns())}')
    while True:
        # start subscription thread
        sub_thread = threading.Thread(target=subscription_worker, args=(client, subscription_request, queue))
        sub_thread.daemon = True
        sub_thread.start()

        last_update = time.time()
        updates_collected = []

        while True:
            try:
                print(f'Update time {ns_to_datetime_str(time_ns())}')
                update = queue.get(timeout=1)  # wait up to 1s for next update
                last_update = time.time()

                info = extract_sr_te_policy_info(update)
                if info is None:
                    continue

                updates_collected.append(info)

                print(
                    f"ts={info['timestamp']} "
                    f"to={info['to_address']} "
                    f"color={info['color']} "
                    f"bytes={info['bytes']} "
                )
            except Empty:
                # no update received in 1 second → break and resubscribe
                break

        print(f"Collected {len(updates_collected)} updates. Sleeping 10s before resubscribe...")
        time.sleep(10)

'''




arista_router = {
    'target': '192.168.102.107', 
    'port': 6030,               # default gNMI port
    'username': 'admin',
    'password': 'admin',
    'insecure': True             # set False if using valid TLS certs
}



paths = [
    "/network-instances/network-instance[name=default]/segment-routing/te-policies"
    ]

with gNMIclient(target=(arista_router['target'], arista_router['port']),
                username=arista_router['username'],
                password=arista_router['password'],
                insecure=arista_router['insecure']) as client:


    # Perform gNMI GET
    #caps = client.capabilities()
    #print(json.dumps(caps, indent=2))
    result = client.get(path=paths, encoding='json_ietf', datatype='CONFIG')
    result = client.get(path=paths, encoding='json_ietf')

print(json.dumps(result, indent=2))

