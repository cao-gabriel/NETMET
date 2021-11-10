"""Packet pair method."""

import argparse
import socket
import time


def server():
    # Instantiate the socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("", 12000))

    # Receive the pair packets
    times = []
    while len(times) < 2:
        message, address = server_socket.recvfrom(1500)
        times.append(time.perf_counter())

    # Packet size (bytes)
    packet_size = 1500

    # Speed calculation (bits/sec)
    bandwidth = packet_size * 8 / (times[1] - times[0])

    # Display the output
    print(f"- Bandwidth : {bandwidth/1_000_000:.1f} Mbits/sec")


def client(destination):
    # Instantiate the socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Get the address from args
    addr = (destination, 12000)

    # Send the first packet of 1500 bytes
    client_socket.sendto(bytes(0x10) * 92, addr)
    first = time.perf_counter()

    # Send the second packet of 1500 bytes
    payload = client_socket.sendto(bytes(0x10) * 92, addr)
    second = time.perf_counter()

    # Display the output
    print(f"- Packet size : {28 + payload} bytes")
    print(f"- Gap time : {((second - first) * 1_000_000):.2f} µsec")


if __name__ == "__main__":
    # Arguments parsing
    parser = argparse.ArgumentParser(prog="traceroute")
    parser.add_argument("-s", "--server", action="store_true", help="Server side.")
    parser.add_argument("-c", "--client", help="Client side.")
    args = parser.parse_args()

    # The user cannot specify server AND client
    if args.server and args.client:
        raise ValueError("Please choose server/client side.")

    # Run the specified side
    if args.server:
        server()
    else:
        client(args.client)
