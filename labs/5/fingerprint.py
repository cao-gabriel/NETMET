#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Nov 13 18:23:09 2021

@author: root
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Nov 10 13:15:35 2021

@author: root
"""

# %% Functions definition
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1
from json import dumps
MAX_TTL = 30
TIMEOUT = 3
DESTINATIONS = ["128.104.159.131", "128.104.159.130", "128.104.159.128"]


def time_exceeded_ttl(destinations):
    '''
    Execute a traceroute on each ip adress in the given parameter 'destinations'
    and retrieve the ip adress and the ttl in the packet sent by each router of
    the path. If a router doesn't send back a packet, the router will be ignored.

    Parameters
    ----------
    destinations : List of string
        A list containing IP adresses that will be tracerouted.

    Returns
    -------
    ip_traceroute_ttl : Dictionary
        A dictionary which keys are the IP adresses of routers and values are
        the TTL in the Time Exceeded packet sent by a router during a traceroute.
        If a router didn't answer a probe, it will not be in the dicitonary.

    '''
    ip_traceroute_ttl = {} # key = ip value = traceroute ttl
    for destination in destinations:
        ttl = 1
        reply = False
        print(f"Traceroute to {destination}")
        while ttl <= MAX_TTL and not reply:
            traceroute_probe = IP(dst = destination, ttl = ttl) / ICMP()
            probe_response = sr1(traceroute_probe, timeout = TIMEOUT, verbose = False)
            if probe_response is not None:
                reply = probe_response[ICMP] == 0
                if not reply:
                    router_ip = probe_response[IP].src
                    router_ttl = probe_response[IP].ttl
                    print("\t IP = {: <22} TTL = {}".format(router_ip, router_ttl))
                    ip_traceroute_ttl[router_ip] = router_ttl
            ttl += 1
            
    return ip_traceroute_ttl

def echo_reply_ttl(ip_list):
    '''
    Execute a ping to each IP adress in the given parameter ip_list and retrieve
    the TTL in the echo reply packet sent by the machine identified by this ip adress.
    If no packet is sent back by the machine. The machine will be ignored.

    Parameters
    ----------
    ip_list : List of string
        A list containing IP adresses that will be pinged.

    Returns
    -------
    ip_ping_ttl : Dictionary
        A dictionary which keys are the IP adresses of machines and values are
        the TTL in the ECHO Reply packet sent by the machine during a PING. If
        a machine didn't respond to a PING, it will not be in the dictionary.

    '''
    ip_ping_ttl = {}
    print("Ping")
    for ip in ip_list:  
        ping = IP(dst = ip) / ICMP()
        ping_response = sr1(ping, timeout = TIMEOUT, verbose = False)
        if ping_response is not None:
            router_ttl = ping_response[IP].ttl
            ip_ping_ttl[ip] = router_ttl
            print("\t IP = {: <22} TTL = {}".format(ip, router_ttl))
    return ip_ping_ttl

def build_database(my_time_exceeded_ttl, my_echo_reply_ttl):
    '''
    Classify IP adresses present in both given parameters according to their TTL
    signature

    Parameters
    ----------
    my_time_exceeded_ttl : Dictionary
        A dictionary returned by the function time_exceeded_ttl.
    my_echo_reply_ttl : TYPE
        A dictionary returned by the function echo_reply_ttl.

    Returns
    -------
    my_database : Dictionary of dictionary of lists
        This is a database classifying IP adresses according to their TTL signature.
        The keys of the dictionaries value of TTLs. For instance, my_database[40][40]
        will give all IP adresses with the TTL signature (40,40)

    '''
    my_database = {}
    intersection_ip = set(my_time_exceeded_ttl.keys()).intersection(set(my_echo_reply_ttl.keys()))
    for ip in intersection_ip:
        traceroute_ttl = my_time_exceeded_ttl[ip]
        ping_ttl = my_echo_reply_ttl[ip]
        if ping_ttl not in my_database:
            my_database[ping_ttl] = {}
            my_database[ping_ttl][traceroute_ttl] = [ip]
        else:
            if traceroute_ttl in my_database[ping_ttl]:
                my_database[ping_ttl][traceroute_ttl].append(ip)
            else:
                my_database[ping_ttl][traceroute_ttl] = [ip]
    return my_database

#%% Running
if __name__ == "__main__":
    my_time_exceeded_ttl = time_exceeded_ttl(DESTINATIONS)
    my_echo_reply_ttl = echo_reply_ttl(my_time_exceeded_ttl.keys())
    my_database = build_database(my_time_exceeded_ttl, my_echo_reply_ttl)
    for ping_ttl in my_database:
        for traceroute_ttl in my_database[ping_ttl]:
            print("({:<3}, {:<3}) : ".format(ping_ttl, traceroute_ttl), end="|")
            for ip in my_database[ping_ttl][traceroute_ttl]:
                print("{:<16}".format(ip), end = "")
            print()
