"""Perform a traceroute."""

import argparse
import requests
import socket
import time
import whois as ws

from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr, sr1


class SimpleTraceroute(object):
    """Simple Traceroute.

    The requests are made iteratively in order.
    There is one request per TTL.
    We rely on Scapy request / response association.

    Optional: whois -- Perform whois request.
    Optional: asns  -- Perform request to RIPE to get the AS number(s).
    """

    def __init__(
        self,
        max_ttl: int = 30,
        max_probes: int = 1,  # Only for interface compatibility
        timeout: int = 3,
        whois: bool = False,
        asns: bool = False,
    ):
        self.max_ttl = max_ttl
        self.timeout = timeout
        self.whois = whois
        self.asns = asns

    def get_whois_info(self, ip):
        """Get whois information."""
        info = ws.whois(ip)
        try:
            name_server = info.name_servers[0]
        except (TypeError, IndexError):
            name_server = None
        return info.country, info.city, name_server

    def get_asns(self, ip):
        """Get RIPE info."""
        info = requests.get(
            f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}"
        ).json()
        try:
            # We get the number of the all AS if any.
            return [asn["asn"] for asn in info["data"]["asns"]]
        except (KeyError, IndexError):
            return []

    def compute(self, destination):
        """Compute the traceroute."""
        for ttl in range(1, self.max_ttl + 1):
            # Forge the request.
            request = IP(dst=destination, ttl=ttl) / UDP(dport=33434)

            # Send the request and get the response.
            response = sr1(request, timeout=self.timeout, verbose=False)

            if response is None:
                # We didn't get the response so we display `*` and carry on to the next.
                print(ttl, "*")
                continue

            # We display the response depending if whois is requested.
            rtt = (response.time - request.time) * 1000
            route_string = [ttl, socket.getfqdn(response.src), f"{rtt:.3f}ms"]
            if self.whois:
                whois_info = self.get_whois_info(response.src)
                [route_string.append(info) for info in whois_info if info]
            if self.asns:
                asns = self.get_asns(response.src)
                [route_string.append(asn) for asn in asns]

            print(*route_string)

            # type == 3 means `dst-port-unreachable` : we reached the target.
            if response.type == 3:
                break


class OptimizedTraceroute(object):
    """Optimized traceroute.

    Make all requests at once and rely on the destination number
    to infer the request TTL.

    Also, we don't rely on Scapy request / response association.

    Finally, add the possibility to make several requests for each TTL (default 3).

    Optional: whois -- Perform whois request.
    Optional: asns  -- Perform request to RIPE to get the AS number(s).
    """

    def __init__(
        self,
        max_ttl: int = 30,
        max_probes: int = 3,
        timeout: int = 3,
        whois: bool = False,
        asns: bool = False,
    ):
        self.max_ttl = max_ttl
        self.max_probes = max_probes
        self.timeout = timeout
        self.whois = whois
        self.asns = asns

    def get_whois_info(self, ip):
        """Get whois information."""
        info = ws.whois(ip)
        try:
            name_server = info.name_servers[0]
        except (TypeError, IndexError):
            name_server = None
        return info.country, info.city, name_server

    def get_asns(self, ip):
        """Get RIPE info."""
        info = requests.get(
            f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}"
        ).json()
        try:
            # We get the number of the all AS if any.
            return [asn["asn"] for asn in info["data"]["asns"]]
        except (KeyError, IndexError):
            return []

    def compute(self, destination):
        """Execute a traceroute on the given destination."""
        # Forge all the requests.
        requests = [
            IP(dst=destination, ttl=ttl) / UDP(dport=33433 + ttl)
            for ttl in range(1, self.max_ttl + 1)
            for _ in range(self.max_probes)
        ]

        # Measure start time.
        start_time = time.time()

        # Send all requests and get responses in no particular order.
        responses = sr(requests, timeout=self.timeout, verbose=False)

        # Remove the request association since because it's cheating !
        # In the same time, construct a dict with TTL as key.
        responses_by_ttl = {}
        for response in responses[0]:
            try:
                # We assume that there is already a response list for the TTL.
                responses_by_ttl[response[1].dport - 33433].append(response[1])
            except KeyError:
                # If there is no response yet for the TTL, we create the first entry.
                responses_by_ttl[response[1].dport - 33433] = [response[1]]

        for i in range(1, self.max_ttl + 1):
            try:
                # We assume there is responses and we get it.
                responses_i = responses_by_ttl[i]
            except KeyError:
                # We don't recieved any response for that TTL :'(
                print(i, "* " * self.max_probes)
                continue

            # We get the response info from the first response for simplicity.
            response = responses_i[0]

            # We create the RTT string output.
            rtt_string = ""
            for np in range(self.max_probes):
                try:
                    # We assume there is a i-nth response.
                    rtt_i = (responses_i[np].time - start_time) * 1000
                    rtt_string += f"{rtt_i:.3f}ms "
                except IndexError:
                    # If there is no i-nth response, we display `*`.
                    rtt_string += "* "

            # We display the response depending if whois requested.
            route_string = [i, socket.getfqdn(response.src), rtt_string]
            if self.whois:
                whois_info = self.get_whois_info(response.src)
                [route_string.append(info) for info in whois_info if info]
            if self.asns:
                asns = self.get_asns(response.src)
                [route_string.append(asn) for asn in asns]

            print(*route_string)

            # type == 3 means `dst-port-unreachable` : we reached the target.
            if response.type == 3:
                break


if __name__ == "__main__":
    # Script arguments parsing
    parser = argparse.ArgumentParser(prog="traceroute")
    parser.add_argument("destination")
    parser.add_argument(
        "-o", "--optimized", action="store_true", help="Optimized traceroute."
    )

    parser.add_argument("-m", "--max-ttl", help="Max TTL.", type=int, default=30)
    parser.add_argument(
        "-p", "--max-probes", help="Max probes per TTL.", type=int, default=3
    )
    parser.add_argument(
        "-t", "--timeout", help="Response timeout in seconds", type=int, default=3
    )

    parser.add_argument("-w", "--whois", action="store_true", help="Request whois.")
    parser.add_argument("-a", "--asn", action="store_true", help="Request AS number.")
    args = parser.parse_args()

    # Select the traceroute depending of the optimized option.
    traceroute_class = OptimizedTraceroute if args.optimized else SimpleTraceroute

    # Instantiate the traceroute with options
    traceroute = traceroute_class(
        max_ttl=args.max_ttl,
        max_probes=args.max_probes,
        timeout=args.timeout,
        whois=args.whois,
        asns=args.asn,
    )

    # Compute the traceroute on the destination
    traceroute.compute(args.destination)
