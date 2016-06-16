"""holds application level settings"""


class Options(object):
    """holds options"""
    def __init__(self, platform, args):
        self.platform = platform
        self.prom = False
        self.write_to_file = False
        self.limit = False

    def get_platform(self):
        """returns a string representing if the OS in Windows, Linux, Unknown"""
        if 'win' in self.platform.lowercase():
            return "win"

        elif 'linux' in self.platform.lowercase():
            return "linux"

        return "Unknown"

    def is_promiscuous(self):
        """returns true if promisuos mode is set"""
        return self.prom
