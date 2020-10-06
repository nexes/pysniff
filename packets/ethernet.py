"""common funtions for eithernet packets"""

import sys
import struct
import socket
from binascii import hexlify
from ctypes import Structure, c_short, c_char

if 'linux' or 'darwin' in sys.platform:
    import fcntl
    SIOCGIFFLAGS = 0x8913 #/usr/include/linux/sockios.h
    SIOCSIFFLAGS = 0x8914 #/usr/include/linux/sockios.h
    IFF_PROMISC = 0x100 #/usr/include/net/if.h


class ifreq(Structure):
    """IF struct for socket flags"""
    _fields_ = [
        ("ifr_name", c_char * 16),
        ("ifr_flags", c_short)
    ]

def set_promiscuous_mode_off(sock):
    """turns off promisuous mode on NIC"""

    if sys.platform in ['linux', 'darwin']:
        sock_fields = ifreq(ifr_name=b"en0")

        fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, sock_fields)
        sock_fields.ifr_flags &= ~IFF_PROMISC

        fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, sock_fields)

    elif 'win' == sys.platform:
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

def set_promiscuous_mode_on(sock):
    """if windows, set to promiscuous mode"""

    if sys.platform in ['linux', 'darwin']:
        sock_fields = ifreq(ifr_name=b"en0")

        fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, sock_fields)
        sock_fields.ifr_flags |= IFF_PROMISC

        fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, sock_fields)

    elif 'win' == sys.platform:
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

def get_protocol(prot_id):
    """returns ascii version of protol based on numerica input value
       some common but not extensive IP protocols.
    """
    d = {
        0: "HOPOPT",
        1: "IMCP",
        2: "IGMP",
        3: "GGP",
        4: "IP-in-IP",
        5: "ST",
        6: "TCP",
        7: "CBT",
        8: "EGP",
        9: "IGP",
        10: "BBN-RCC-MON",
        11: "NVP-II",
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

        return {
            "version": p_version,
            "size": p_length,
            "id": p_id,
            "ttl": p_ttl,
            "type": p_type,
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "data": data
        }

    elif 'linux' in sys.platform:
        header = struct.unpack("!6s6sH", packet[:14])
        src_mac = hexlify(header[0])
        dest_mac = hexlify(header[1])
        eth_type = header[2]
        payload = packet[14:]

        if eth_type & 0x0800:
            ip_header = struct.unpack("!BBHHHBBH4s4s", payload[:20])
            p_version = ip_header[0] >> 4
            p_length = ip_header[2]
            p_id = ip_header[3]
            p_ttl = ip_header[5]
            p_type = get_protocol(ip_header[6])
            src_ip = socket.inet_ntoa(ip_header[8])
            dest_ip = socket.inet_ntoa(ip_header[9])
            data = payload[20:]

        return {
            "version": p_version,
            "size": p_length,
            "id": p_id,
            "ttl": p_ttl,
            "type": p_type,
            "src_mac": src_mac,
            "dest_mac": dest_mac,
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "data": data
        }
