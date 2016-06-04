"""TCP class packets"""
import struct


class TCP(object):
    """Class representing a tcp packet"""

    def __init__(self, packet):
        """pass in the tcp packet to be parsed"""
        self.__packet = struct.unpack("!HH2I2H2H", packet[:20])

        self.src_port = self.__packet[0]
        self.dest_port = self.__packet[1]
        self.seq_number = self.__packet[2]
        self.ack_number = self.__packet[3]
        self.flags = self.__packet[4]
        self.window_size = self.__packet[5]
        self.checksum = self.__packet[6]
        self.urg = self.__packet[7]
        # self.data = packet[20:]
