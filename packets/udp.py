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

    def print_header(self):
        """prints UDP header information"""
        print("\tSource port: {} Destination port: {}".format(self.src_port, self.dest_port))
        print("\tHeader size: {} Checksum: {}".format(self.length, self.checksum))
        print("\t{:-^80s}\n".format("-"))

    def print_data(self):
        """prints UDP payload information"""
        print("{}".format(self.data))
