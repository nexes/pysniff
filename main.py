# pylint: disable=C0103

"""sniffing for sockets"""
import socket
import sys
from packets import TCP, UDP, ethernet
from options import Options

PACKET_SIZE = 65535


if __name__ == '__main__':
    opts = Options(sys.platform, sys.argv)
    capture = None

    if opts.get_platform() == 'win':
        capture = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        #reuse address
        capture.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        capture.bind(
            (socket.gethostbyname(socket.gethostname()), 0)
        )

        if opts.is_promiscuous():
            ethernet.set_promiscuous_mode_on(capture)

    elif opts.get_platform() == 'linux':
        capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x03))

        if opts.is_promiscuous():
            ethernet.set_promiscuous_mode_on(capture)

    i = 0
    while i < 20:
        i = i + 1
        raw_packet = capture.recv(PACKET_SIZE)
        packet = ethernet.parse_header(raw_packet)
        src_ip = packet.get("src_ip")
        dest_ip = packet.get("dest_ip")
        src_mac = packet.get("src_mac", "-")
        dest_mac = packet.get("dest_mac", "-")

        print(
            "Source IP: {} Destination IP: {} Source MAC: {} Destination MAC: {}\n"
            .format(src_ip, dest_ip, src_mac, dest_mac),

            "\tVersion: {} Size: {} \tID: {} \tTTL: {}   Type: {}\n"
            .format(packet.get("version"), packet.get("size"), packet.get("id"), packet.get("ttl"), packet.get("type"))
        )

        if packet["type"] is "TCP":
            tcp = TCP(packet["data"])
            tcp.print_header()
            tcp.print_data()

        elif packet["type"] is "UDP":
            udp = UDP(packet["data"])
            udp.print_header()
            udp.print_data()

    if opts.is_promiscuous():
        ethernet.set_promiscuous_mode_off(capture)

    capture.close()
