#!/usr/bin/env python3
import random


class SamplingMock:
    def __init__(self):
        self.policies = [
            {"color": 101, "endpoint": "2.2.2.2", "router_id": "1.1.1.1", "rate_gbps": 5, "last_counter": 0},
            {"color": 101, "endpoint": "7.7.7.7", "router_id": "1.1.1.1", "rate_gbps": 5, "last_counter": 0},
            {"color": 101, "endpoint": "8.8.8.8", "router_id": "1.1.1.1", "rate_gbps": 5, "last_counter": 0},
            {"color": 101, "endpoint": "1.1.1.1", "router_id": "2.2.2.2", "rate_gbps": 5, "last_counter": 0},
            {"color": 101, "endpoint": "7.7.7.7", "router_id": "2.2.2.2", "rate_gbps": 5, "last_counter": 0},
            {"color": 101, "endpoint": "8.8.8.8", "router_id": "2.2.2.2", "rate_gbps": 5, "last_counter": 0},
            {"color": 101, "endpoint": "1.1.1.1", "router_id": "7.7.7.7", "rate_gbps": 5, "last_counter": 0},
            {"color": 101, "endpoint": "2.2.2.2", "router_id": "7.7.7.7", "rate_gbps": 5, "last_counter": 0},
            {"color": 101, "endpoint": "8.8.8.8", "router_id": "7.7.7.7", "rate_gbps": 5, "last_counter": 0},
            {"color": 101, "endpoint": "1.1.1.1", "router_id": "8.8.8.8", "rate_gbps": 5, "last_counter": 0},
            {"color": 101, "endpoint": "2.2.2.2", "router_id": "8.8.8.8", "rate_gbps": 5, "last_counter": 0},
            {"color": 101, "endpoint": "7.7.7.7", "router_id": "8.8.8.8", "rate_gbps": 5, "last_counter": 0},
            {"color": 202, "endpoint": "2.2.2.2", "router_id": "1.1.1.1", "rate_gbps": 40, "last_counter": 0},
            {"color": 202, "endpoint": "7.7.7.7", "router_id": "1.1.1.1", "rate_gbps": 40, "last_counter": 0},
            {"color": 202, "endpoint": "8.8.8.8", "router_id": "1.1.1.1", "rate_gbps": 40, "last_counter": 0},
            {"color": 202, "endpoint": "1.1.1.1", "router_id": "2.2.2.2", "rate_gbps": 40, "last_counter": 0},
            {"color": 202, "endpoint": "7.7.7.7", "router_id": "2.2.2.2", "rate_gbps": 40, "last_counter": 0},
            {"color": 202, "endpoint": "8.8.8.8", "router_id": "2.2.2.2", "rate_gbps": 40, "last_counter": 0},
            {"color": 202, "endpoint": "1.1.1.1", "router_id": "7.7.7.7", "rate_gbps": 40, "last_counter": 0},
            {"color": 202, "endpoint": "2.2.2.2", "router_id": "7.7.7.7", "rate_gbps": 40, "last_counter": 0},
            {"color": 202, "endpoint": "8.8.8.8", "router_id": "7.7.7.7", "rate_gbps": 40, "last_counter": 0},
            {"color": 202, "endpoint": "1.1.1.1", "router_id": "8.8.8.8", "rate_gbps": 40, "last_counter": 0},
            {"color": 202, "endpoint": "2.2.2.2", "router_id": "8.8.8.8", "rate_gbps": 40, "last_counter": 0},
            {"color": 202, "endpoint": "7.7.7.7", "router_id": "8.8.8.8", "rate_gbps": 40, "last_counter": 0}
        ]


    @staticmethod
    def jitter(value, pct=0.05):
        delta = value * pct
        return int(random.uniform(value - delta, value + delta))


    @staticmethod
    def bytes_for_rate(rate_gbps, interval_seconds):
        bytes_per_sec = rate_gbps * 1_000_000_000 / 8
        return int(bytes_per_sec * interval_seconds)
    

    def return_srte_counter(self, policy_info, sampling_interval):
        for existing_policy in self.policies:
            if policy_info["color"] == existing_policy["color"] and policy_info["endpoint"] == existing_policy["endpoint"] and policy_info["router_id"] == existing_policy["router_id"]:
                current_rate = self.jitter(self.bytes_for_rate(existing_policy["rate_gbps"], sampling_interval))
                new_counter = existing_policy["last_counter"] + current_rate
                existing_policy["last_counter"] = new_counter
                return new_counter
        return 0