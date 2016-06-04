"""UDP class packets"""
import struct


class UDP(object):
    """Class representing a udp packet"""

    def __init__(self, packet):
        """Class representing a udp packet"""
        self.__packet = struct.unpack("!4H", packet[:8])

        self.src_port = self.__packet[0]
        self.dest_port = self.__packet[1]
        self.length = self.__packet[2]
        self.checksum = self.__packet[3]
        self.data = packet[8:]
