# pylint: disable=C0103

"""sniffing for sockets"""
import socket
import sys
from packets import TCP, UDP, ethernet
from options import Options

PACKET_SIZE = 65535


if __name__ == '__main__':
    opts = Options(sys.platform)
    packets_count = opts.capture_count()
    packets_file = opts.output_file()
    count = 0
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

    while True:
        if packets_count is not None:
            if count < packets_count:
                count = count + 1
            else:
                break

        raw_packet = capture.recv(PACKET_SIZE)
        packet = ethernet.parse_header(raw_packet)
        src_ip = packet.get("src_ip")
        dest_ip = packet.get("dest_ip")
        src_mac = packet.get("src_mac", "-")
        dest_mac = packet.get("dest_mac", "-")

        # ugly oh man is this ugly
        info = "Source IP: {} Destination IP: {} Source MAC: {} Destination MAC: {}\n \
                \tVersion: {} Size: {} \tID: {} \tTTL: {}   Type: {}\n \
                ".format(src_ip, dest_ip, src_mac, dest_mac, packet.get("version"), packet.get("size"), packet.get("id"), packet.get("ttl"), packet.get("type"))

        if packets_file is not None:
            with open(packets_file, 'a', encoding='utf-8') as f:
                f.write(info)
        else:
            print(info)

        if packet["type"] is "TCP":
            tcp = TCP(packet["data"])
            if packets_file is not None:
                tcp.write_header(packets_file)
                tcp.write_data(packets_file)
            else:
                tcp.print_header()
                tcp.print_data()

        elif packet["type"] is "UDP":
            udp = UDP(packet["data"])
            if packets_file is not None:
                udp.write_header(packets_file)
                udp.write_data(packets_file)
            else:
                udp.print_header()
                udp.print_data()

    if opts.is_promiscuous():
        ethernet.set_promiscuous_mode_off(capture)

    capture.close()
