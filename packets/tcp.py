"""TCP class packets"""
import struct


class TCP(object):
    """Class representing a tcp packet"""

    def __init__(self, packet):
        """pass in the tcp packet to be parsed"""
        __packet = struct.unpack("!HH2I2H2H", packet[:20])

        self.src_port = __packet[0]
        self.dest_port = __packet[1]
        self.seq_number = __packet[2]
        self.ack_number = __packet[3]
        self.flags = {
            "NS ": (__packet[4] & 0x80) >> 0x07,
            "CWR": (__packet[4] & 0x100) >> 0x08,
            "ECE": (__packet[4] & 0x200) >> 0x09,
            "URG": (__packet[4] & 0x400) >> 0x0a,
            "ACK": (__packet[4] & 0x800) >> 0x0b,
            "PSH": (__packet[4] & 0x1000) >> 0x0c,
            "RST": (__packet[4] & 0x2000) >> 0x0d,
            "SYN": (__packet[4] & 0x4000) >> 0x0e,
            "FIN": (__packet[4] & 0x8000) >> 0x0f
        }
        self.window_size = __packet[5]
        self.checksum = __packet[6]
        self.urg = __packet[7]
        self.data = packet[20:]

    def print_header(self):
        """prints TCP header information"""
        print("\tSource port: {: <5d} Destination port: {: <5d}\n".format(self.src_port, self.dest_port))

        line_break = 0
        for key, value in self.flags.items():
            line_break = line_break + 1
            print("\t", "{:<4s}: {: <1d}".format(key, value), end=' ')

            if line_break is 4:
                print()

        print(
            "\n\n\t",
            "Seq number: {} ACK number: {} Checksum: {}\n".format(self.seq_number, self.ack_number, self.checksum),
            "\t{:-^80s}\n".format("-")
        )

    def print_data(self):
        """prints TCP data information"""
        pass
