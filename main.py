# pylint: disable=C0103

"""sniffing for sockets"""
import socket
import sys

from packets import TCP, UDP, ethernet

PACKET_SIZE = 65535


if __name__ == '__main__':
    platform = sys.platform
    capture = None

    if 'win' in platform:
        capture = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        #reuse address
        capture.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        capture.bind(
            (socket.gethostbyname(socket.gethostname()), 0)
        )
        ethernet.set_promiscuous_mode_on(capture)

    elif 'linux' in platform:
        capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x03))
        ethernet.set_promiscuous_mode_on(capture)

    i = 0
    while i < 15:
        i = i + 1
        raw_packet = capture.recv(PACKET_SIZE)
        ver, length, pId, ttl, pType, src, dest, payload = ethernet.parse_header(raw_packet)

        print(
            "Version: {} Size: {} \tID: {} \tTTL: {}   Type: {} \tSource IP: {} Destination IP:{}"
            .format(ver, length, pId, ttl, pType, src, dest)
        )

        if pType is "TCP":
            tcp = TCP(payload)
            tcp.print_header()

        elif pType is "UDP":
            udp = UDP(payload)
            udp.print_header()

    ethernet.set_promiscuous_mode_off(capture)
    capture.close()
