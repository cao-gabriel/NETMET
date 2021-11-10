#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Nov 10 13:15:35 2021

@author: root
"""

#%% Functions definition
from scapy.layers.inet import IP, UDP, ICMP
from scapy.sendrecv import sr, sr1

MAX_TTL = 30
TIMEOUT = 3
destinations = ["google.com", "facebook.com"]

def my_traceroute(destination):
    """Compute the traceroute."""
    for ttl in range(1, MAX_TTL + 1):
        # Forge the request.
        request = IP(dst=destination, ttl=ttl) / UDP(dport=33434)

        # Send the request and get the response.
        response = sr1(request, timeout=TIMEOUT, verbose=False)
        if response is None:
            # We didn't get the response so we display `*` and carry on to the next.
            print(ttl, "*")
            continue
        # type == 3 means `dst-port-unreachable` : we reached the target.
        print(response[IP].src)

        if response.type == 3:
            break
def check_aliases(destinations):
    '''
    Groups ip routers coming from the same router

    Parameters
    ----------
    ip_routers : string list
        List of destinations.

    Returns
    -------
    None.

    '''
    for destination in destinations:
        my_ping = IP(dst = destination) / ICMP()
        my_response = sr1(my_ping, verbose = 0)
        print(my_response[IP].ttl)
        
#%% Running

#check_aliases(destinations)
my_traceroute("google.com")