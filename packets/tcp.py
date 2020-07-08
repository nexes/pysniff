"""TCP class packets"""
import struct
import textwrap


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

        dataType = "TCP"
        line_break = 0
        for key, value in self.flags.items():
            line_break = line_break + 1
            print("\t", "{:<4s}: {: <1d}".format(key, value), end=' ')

            if line_break is 4:
                print()

        if self.src_port == 80 or self.dest_port == 80:
            dataType = "HTTP"
        
        print(
            "\n\n\t",
            "Seq number: {} ACK number: {} Checksum: {} Data Type: {}\n".format(self.seq_number, self.ack_number, self.checksum, dataType)
        )

    def print_data(self):
        """prints TCP data information"""
        data_strs = textwrap.wrap(str(self.data), width=80)

        for line in data_strs:
            print("\t\t", "{}".format(line))

        print("{:-<90s}\n".format("-"))

    def write_header(self, filename):
        """writes TCP header information"""
        dataType = "TCP"
        if self.src_port == 80 or self.dest_port == 80:
            dataType = "HTTP"

        _info = "\tSource port: {: <5d} Destination port: {: <5d}\n".format(self.src_port, self.dest_port)
        _info2 ="\n\tSeq number: {} ACK number: {} Checksum: {} Data Type: {}\n".format(self.seq_number, self.ack_number, self.checksum, dataType)
        _flags = " "

        line_break = 0
        for key, value in self.flags.items():
            line_break = line_break + 1
            _flags = _flags + "\t{:<4s}: {: <1d}".format(key, value)

            if line_break is 4:
                _flags = _flags + "\n"

        with open(filename, 'a', encoding='utf-8') as f:
            f.write(_info)
            f.write(_flags)
            f.write(_info2)

    def write_data(self, filename):
        """writes TCP data information"""
        data_strs = textwrap.wrap(str(self.data), width=80)
        _data = "\n"

        for line in data_strs:
            _data = _data + "\t\t{}\n".format(line)

        with open(filename, 'a', encoding='utf-8') as f:
            f.write(_data)
            f.write("{:-<90s}\n".format("-"))
