# pylint: disable=C0103

"""sniffing for sockets"""
import socket
import sys
import struct
from ctypes import Structure, c_short, c_char

from packets import TCP, UDP

if 'linux' in sys.platform:
    import fcntl
    SIOCGIFFLAGS = 0x8913
    SIOCSIFFLAGS = 0x8914
    IFF_PROMISC = 0x100

PACKET_SIZE = 65535


class ifreq(Structure):
    """IF struct for socket flags"""
    _fields_ = [
        ("ifr_name", c_char * 16),
        ("ifr_flags", c_short)]


def set_promiscuous_mode_off(sock):
    """turns off promisuous mode on NIC"""

    if 'linux' in sys.platform:
        sock_fields = ifreq(ifr_name=b"wlp2s0")

        fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, sock_fields)
        sock_fields.ifr_flags &= ~IFF_PROMISC

        fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, sock_fields)

    elif 'win' in sys.platform:
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

def set_promiscuous_mode_on(sock):
    """if windows, set to promiscuous mode"""

    if 'linux' in sys.platform:
        sock_fields = ifreq(ifr_name=b"wlp2s0")

        fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, sock_fields)
        sock_fields.ifr_flags |= IFF_PROMISC

        fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, sock_fields)

    elif 'win' in sys.platform:
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)


def get_protocol(prot_id):
    """returns ascii version of protol based on numerica input value"""
    d = {
        0: "HOPOPT",
        1: "IMCP",
        6: "TCP",
        8: "EGP",
        9: "IGP",
        17: "UDP",
        27: "RDP",
        18: "MUX",
        50: "ESP",
        52: "NLSP",
        56: "TLSP",
        57: "SKIP",
        89: "OSPF"
    }

    return d.get(prot_id, "UNKNOWN: {}".format(prot_id))

def ip_ascii(addr_id):
    """returns a string representation of the IP address from number given"""
    # oct1 = (addr_id & 0xFF000000) >> 24
    # oct2 = (addr_id & 0x00FF0000) >> 16
    # oct3 = (addr_id & 0x0000FF00) >> 8
    # oct4 = addr_id & 0x000000FF

    return "{}.{}.{}.{}".format(addr_id[0], addr_id[1], addr_id[2], addr_id[3])

def print_header(packet):
    """parse network packet. Returns what kind of packet this is, TCP, UDP etc etc"""
    header = packet[:20]
    payload = struct.unpack("!BBHHHBBH4s4s", header)

    version = payload[0] >> 4
    size = payload[2]
    ident = payload[3]
    packet_type = get_protocol(payload[6])
    ttl = payload[5]
    source_ip = socket.inet_ntoa(payload[8])
    dest_ip = socket.inet_ntoa(payload[9])

    print(
        "ver: {}  prot: {}\t TTL: {}    size: {} bytes\t ID: {}\t source: {}\t destination {}"
        .format(version, packet_type, ttl, size, ident, source_ip, dest_ip)
    )

    return packet_type

if __name__ == '__main__':
    capture = None

    if 'win' in sys.platform:
        capture = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        capture.bind(
            (socket.gethostbyname(socket.gethostname()), 0)
        )
        #include the packet header info
        capture.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        set_promiscuous_mode_on(capture)

    elif 'linux' in sys.platform:
        capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x03))

    #reuse address, not left in TIME_WAIT
    capture.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    i = 0
    while i < 10:
        i = i + 1
        raw_packet = capture.recv(PACKET_SIZE)
        packet_t = print_header(raw_packet)

        if packet_t is "TCP":
            tcp = TCP(raw_packet[20:])
            print("source port: {}\t destination port: {}".format(tcp.src_port, tcp.dest_port))
            print("sequence number: {}\n".format(tcp.seq_number))

        elif packet_t is "UDP":
            udp = UDP(raw_packet[20:])
            print("source port: {}\t destination port: {}".format(udp.src_port, udp.dest_port))
            print("length: {}\t\t checksum {}\n".format(udp.length, udp.checksum))
            # print("UDP data? {}\n".format(udp.data))


    set_promiscuous_mode_off(capture)
    capture.close()
