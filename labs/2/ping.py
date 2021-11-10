#! /usr/bin/python3.8
"""Perform a ping."""

import argparse
import statistics
import time

from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1

from datetime import datetime


class Ping(object):
    def __init__(self, count=3, wait=1, timeout=3):
        self.count = count
        self.wait = wait
        self.timeout = timeout

    def compute(self, destination):
        """Compute ping process."""
        # Forge ICMP request
        icmp_request = IP(dst=destination) / ICMP(type=8, code=0)
        print(f"PING {destination} ({destination}): {len(icmp_request)} data bytes")

        packet_lost = 0
        rtts = []
        for i in range(self.count):
            # Send the ICMP request
            request_timestamp = datetime.now().timestamp()
            response = sr1(icmp_request, timeout=self.timeout, verbose=False)
            if response is None:
                packet_lost += 1
        
            # Compute the RTT (Round Trip Time)
            rtt = (response.time - request_timestamp) * 1000

            # Output the response
            rtts.append(rtt)
            print(
                f"{len(response)} bytes from {destination}: "
                f"icmp_seq={i} ttl={response.ttl} time={rtt:.3f} ms"
            )

            # Wait before sending the next packet
            time.sleep(self.wait)

        # Statistics header
        print()
        print(f"--- {destination} ping statistics ---")

        # Compute transmission statistics
        packet_transmitted = self.count
        packet_received = self.count - packet_lost
        packet_loss = packet_lost / self.count * 100
        print(
            f"{packet_transmitted} packets transmitted, "
            f"{packet_received} packets received, {packet_loss:.1f}% packet loss"
        )

        # Compute RTT statisticas
        min_rtt = min(rtts)
        avg_rtt = statistics.mean(rtts)
        max_rtt = max(rtts)
        std_rtt = statistics.stdev(rtts)
        print(
            f"round-trip min/avg/max/stddev = "
            f"{min_rtt:.3f}/{avg_rtt:.3f}/{max_rtt:.3f}/{std_rtt:.3f} ms"
        )
		


if __name__ == "__main__":
    # Script arguments parsing
    parser = argparse.ArgumentParser(prog="ping")
    parser.add_argument("destination")
    parser.add_argument(
        "-c",
        "--count",
        help="Stop after send this count of packets",
        type=int,
        default=3,
    )
    parser.add_argument(
        "-i",
        "--wait",
        help="Wait between each packets in seconds",
        type=int,
        default=1,
    )
    parser.add_argument(
        "-t", "--timeout", help="Response timeout in seconds", type=int, default=3
    )

    args = parser.parse_args()

    ping = Ping(count=args.count, timeout=args.timeout, wait=args.wait)
    ping.compute(args.destination)
