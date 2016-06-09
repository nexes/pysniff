# pylint: disable=C0103

"""sniffing for sockets"""
import socket
import sys

from packets import TCP, ethernet


PACKET_SIZE = 65535


if __name__ == '__main__':
    capture = None

    if 'win' in sys.platform:
        capture = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        #reuse address
        capture.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        capture.bind(
            (socket.gethostbyname(socket.gethostname()), 0)
        )
        ethernet.set_promiscuous_mode_on(capture)

    elif 'linux' in sys.platform:
        capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x03))
        ethernet.set_promiscuous_mode_on(capture)

    i = 0
    while i < 5:
        i = i + 1
        raw_packet = capture.recv(PACKET_SIZE)
        ver, length, pId, ttl, pType, src, dest, payload = ethernet.parse_header(raw_packet)

        print(
            "Version: {} Size: {} \tID: {} \tTTL: {}   Type: {} \tSource: {} Destination {}"
            .format(ver, length, pId, ttl, pType, src, dest)
        )

        if pType is "TCP":
            tcp = TCP(payload)
            print("source port: {}\t destination port: {}".format(tcp.src_port, tcp.dest_port))
            print("sequence number: {}\n".format(tcp.seq_number))
            print("\n{}".format(str(tcp.data)))
            print("----------------------------------------------------------------")

        # elif packet_t is "UDP":
        #     udp = UDP(raw_packet[20:])
        #     print("source port: {}\t destination port: {}".format(udp.src_port, udp.dest_port))
        #     print("length: {}\t\t checksum {}\n".format(udp.length, udp.checksum))
        #     # print("UDP data? {}\n".format(udp.data))


    ethernet.set_promiscuous_mode_off(capture)
    capture.close()
