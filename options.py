"""holds application level settings"""
import argparse


class Options(object):
    """holds application level options"""

    def __init__(self, platform):
        self.platform = platform
        self._parser = argparse.ArgumentParser(description="Sniff ethernet packets",
                                               prog="Sniffer.py",
                                               epilog="Sniffer was written by Joe Berria <joeberria@gmail.com>")

        self._parser.add_argument("-p",
                                  "--promiscuous",
                                  action="store_true",
                                  default=False,
                                  help="Puts your NIC in promiscuous mode to capture more packets and differnt types")

        self._parser.add_argument("-o",
                                  "--output",
                                  type=str,
                                  metavar="",
                                  help="Save the output to a file")

        self._parser.add_argument("-l",
                                  "--length",
                                  type=int,
                                  metavar="",
                                  help="Will only capture this amount of packets")

        self.args = self._parser.parse_args()
        print(self.args)

    def get_platform(self):
        """returns a string representing if the OS in Windows, Linux, Unknown"""
        if 'win' in self.platform:
            return "win"

        elif 'linux' in self.platform:
            return "linux"

        return "Unknown"

    def is_promiscuous(self):
        """returns true if promisuos mode is set"""
        return self.args.promiscuous

    def capture_count(self):
        """returns the number of packets to capture or None to run continuously"""
        return self.args.length

    def output_file(self):
        """returns the name of the output file so save the captured packets"""
        pass
