#!/usr/bin/env python3

from pprint import pprint
from time import time
from datetime import timedelta
import copy


class ShowSamplingResponder:
    def __init__(self, sampling_server):
        self.sampling_server = sampling_server


    def sampling_summary(self):
        self.sampling_server.logger.debug(f'Sampling show responder: Sending sampling summmary info')
        sampling_summary = {}
        sampling_summary["sampling_interval"] = self.sampling_server.sampling_options["sampling_interval"]
        sampling_summary["adjust_interval"] = self.sampling_server.sampling_options["adjust_interval"]
        sampling_summary["actual_adjust_interval"] = self.sampling_server.actual_adjust_interval
        sampling_summary["adjust_threshold"] = self.sampling_server.sampling_options["adjust_threshold"]
        sampling_summary["last_adjusted"] = str(timedelta(seconds=int(time()) - self.sampling_server.last_adjust_time))
        sampling_summary["sampling_database_path"] = self.sampling_server.sampling_db_path
        sampling_summary["samplers"] = {}
        for sampler_ip, sampler_state in self.sampling_server.samplers.items():
            sampler_dict = {}
            sampler_dict["valid_config"] = sampler_state.client_settings["valid_config"]
            sampler_dict["running"] = sampler_state.running
            sampler_dict["os"] = sampler_state.client_settings["os"]
            sampler_dict["auth"] = sampler_state.client_settings["auth"]
            sampler_dict["last_read_time"] = str(timedelta(seconds=int(time()) - sampler_state.last_read_time))
            sampling_summary["samplers"][sampler_ip] = sampler_dict
        return sampling_summary


    def sampling_client_detail(self, queried_client):
        self.sampling_server.logger.debug(f'Sampling show responder: Sending sampling client info for {queried_client}')
        sampler_dict = {}
        try:
            sampler_dict["sampler_ip"] = queried_client
            sampler_dict["running"] = self.sampling_server.samplers[queried_client].running
            sampler_dict["sampling_interval"] = self.sampling_server.samplers[queried_client].sampling_interval
            sampler_dict["last_read_time"] = str(timedelta(seconds=int(time()) - self.sampling_server.samplers[queried_client].last_read_time))
            sampler_dict["router_id"] = self.sampling_server.samplers[queried_client].router_id
            sampler_dict["valid_config"] = self.sampling_server.samplers[queried_client].client_settings["valid_config"]
            sampler_dict["invalid_config_reason"] = self.sampling_server.samplers[queried_client].client_settings["invalid_config_reason"]
            sampler_dict["os"] = self.sampling_server.samplers[queried_client].client_settings["os"]
            sampler_dict["port"] = self.sampling_server.samplers[queried_client].client_settings["port"]
            sampler_dict["auth"] = self.sampling_server.samplers[queried_client].client_settings["auth"]
            sampler_dict["username"] = self.sampling_server.samplers[queried_client].client_settings["username"]
            sampler_dict["password"] = self.sampling_server.samplers[queried_client].client_settings["password"]
        except KeyError:
            self.sampling_server.logger.exception(f'Sampling show responder: Unable to send sampling client info for {queried_client}')
        return sampler_dict
    

    def sampling_clients(self, queried_client=None):
        self.sampling_server.logger.debug(f'Sampling show responder: Sending sampling clients info')
        sampler_list = [] 
        if queried_client:
            if queried_client not in self.sampling_server.samplers.keys():
                return {"sampler_list": sampler_list}
            sampler_list.append(self.sampling_client_detail(queried_client))
            return {"sampler_list": sampler_list}
        for queried_client in self.sampling_server.samplers.keys():
            sampler_list.append(self.sampling_client_detail(queried_client))
        return {"sampler_list": sampler_list}


    def sampling_policy(self, queried_policy):
        self.sampling_server.logger.debug(f'Sampling show responder: Sending sampling policy info for {queried_policy}')
        policy_dict = {}
        try:
            policy_dict["router_id"] = self.sampling_server.sampled_policies[queried_policy]["router_id"]
            policy_dict["endpoint"] = self.sampling_server.sampled_policies[queried_policy]["endpoint"]
            policy_dict["color"] = self.sampling_server.sampled_policies[queried_policy]["color"]
            policy_dict["rate_bps"] = self.sampling_server.sampled_policies[queried_policy]["rate_bps"]
            policy_dict["samples"] = self.sampling_server.sampled_policies[queried_policy]["samples"]
            policy_dict["window_seconds"] = self.sampling_server.sampled_policies[queried_policy]["window_seconds"]
            policy_dict["last_updated"] = self.sampling_server.sampled_policies[queried_policy]["last_updated"]
            policy_dict["stale"] = self.sampling_server.sampled_policies[queried_policy]["stale"]
        except KeyError:
            self.sampling_server.logger.exception(f'Sampling show responder: Unable to send sampling policy info for {queried_policy}')
        return policy_dict
    

    def sampling_policies(self, queried_policy=None):
        self.sampling_server.logger.debug(f'Sampling show responder: Sending sampled policies info')
        policies_list = [] 
        if queried_policy:
            if queried_policy not in self.sampling_server.sampled_policies.keys():
                return {"policies_list": policies_list}
            policies_list.append(self.sampling_policy(queried_policy))
            return {"policies_list": policies_list}
        for queried_policy in self.sampling_server.sampled_policies.keys():
            policies_list.append(self.sampling_policy(queried_policy))
        return {"policies_list": policies_list}
    

    
    def sampling_internal(self):
        self.sampling_server.logger.debug(f'Sampling show responder: Sending internal stats')
        sampling_internal = {}
        sampling_internal["running"] = self.sampling_server.running
        sampling_internal["greenthreads_available"] = self.sampling_server.pool.free()
        sampling_internal["config_changes_queued_count"] = self.sampling_server.config_updates.qsize()
        sampling_internal["running_samplers_count"] = len(self.sampling_server.running_samplers)
        sampling_internal["running_samplers"] = self.sampling_server.running_samplers.keys()
        sampling_internal["gnmi_streaming_queue_size"] = self.sampling_server.gnmi_streaming_queue.qsize()
        sampling_internal["sampling_to_bgp_queue"] = self.sampling_server.sampling_to_bgp_queue.qsize()
        sampling_internal["sampled_policies_number"] = len(self.sampling_server.sampled_policies)
        return sampling_internal
    

    RESPONDERS = {
            "sampling_summary": sampling_summary,
            "sampling_clients": sampling_clients,
            "sampling_policies": sampling_policies,
            "sampling_policies_detail": sampling_policies,
            "sampling_internal": sampling_internal,
        }


    def get_response(self, query, command=None):
        self.sampling_server.logger.debug(f'Sampling show responder: Received query {query}, arguments {command}')
        if query not in self.RESPONDERS.keys():
            return
        if command:
            return self.RESPONDERS[query](self, command)
        return self.RESPONDERS[query](self)