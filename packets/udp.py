"""UDP class packets"""
import struct
import textwrap

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
        print("\tHeader size: {} Checksum: {}\n".format(self.length, self.checksum))

    def print_data(self):
        """prints UDP payload information"""
        data_strs = textwrap.wrap(str(self.data), width=80)

        for line in data_strs:
            print("\t\t", "{}".format(line))

        print("{:-<80s}\n".format("-"))

    def write_header(self, filename):
        """write UDP header to file"""
        with open(filename, 'a', encoding='utf-8') as f:
            f.write("\tSource port: {} Destination port: {}\n".format(self.src_port, self.dest_port))
            f.write("\t\tHeader size: {} Checksum: {}\n\n".format(self.length, self.checksum))

    def write_data(self, filename):
        """write UDP data to file"""
        data_strs = textwrap.wrap(str(self.data), width=80)
        data = ""

        for line in data_strs:
            data = data + "\t\t{}\n".format(line)

        with open(filename, 'a', encoding='utf-8') as f:
            f.write(data)
            f.write("{:-<80s}\n".format("-"))
