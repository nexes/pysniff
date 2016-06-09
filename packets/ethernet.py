"""common funtions for eithernet packets"""

import sys
import struct
import socket
from ctypes import Structure, c_short, c_char

if 'linux' in sys.platform:
    import fcntl
    SIOCGIFFLAGS = 0x8913
    SIOCSIFFLAGS = 0x8914
    IFF_PROMISC = 0x100


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
    """returns ascii version of protol based on numerica input value
       some common but not extensive IP protocols.
    """
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

def parse_header(packet):
    """parse network packet. Returns what kind of packet this is, TCP, UDP etc etc"""
    if 'win' in sys.platform:
        header = struct.unpack("!BBHHHBBH4s4s", packet[:20])

        p_version = header[0] >> 4
        p_length = header[2]
        p_id = header[3]
        p_ttl = header[5]
        p_type = get_protocol(header[6])
        src_ip = socket.inet_ntoa(header[8])
        dest_ip = socket.inet_ntoa(header[9])
        data = packet[20:]

        return p_version, p_length, p_id, p_ttl, p_type, src_ip, dest_ip, data

    elif 'linux' in sys.platform:
        #needs to parse ethernet frame, and then the ip frame
        return -1
