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
destinations = ["128.104.159.131", "128.104.159.130", "128.104.159.128"]


def get_ips(destinations, my_database):
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
    routers_ip = set()
    for destination in destinations:
        for ttl in range(1, MAX_TTL + 1):
            print(ttl, end = ' ')
            request = IP(dst=destination, ttl=ttl) / ICMP()
            response = sr1(request, timeout=TIMEOUT, verbose=False)
            if response is None:
                print( "*")
                continue
            else:
                routers_ip.add((response[IP].src, response[IP].ttl))
                print(response[IP].src)
            if response[ICMP].type == 0:
                break
                #response.show()
    return routers_ip

def build_database(routers_ip, my_database):
    for ip, traceroute_ttl in routers_ip:
        my_ping_request = IP(dst = ip) / ICMP()
        my_ping_response = sr1(my_ping_request, timeout=TIMEOUT, verbose = False)
        if my_ping_response is not None:
            ping_ttl = my_ping_response[IP].ttl
            print(ip, traceroute_ttl, ping_ttl)
            if ping_ttl not in my_database:
                my_database[ping_ttl] = {}
                my_database[ping_ttl][traceroute_ttl] = [ip]
            else:
                if traceroute_ttl in my_database:
                    my_database[ping_ttl][traceroute_ttl].append(ip)
                else:
                    my_database[ping_ttl][traceroute_ttl] = [ip]
    
        else:
            print("*")
        
    return my_database
#%% Running
my_database = {}
print(dumps(build_database(get_ips(destinations, my_database), my_database), indent= 4))
