from typing import Optional


class Packet:
    def __init__(self, src=Optional[str], dest=Optional[str], ap_name=Optional[str]):
        self.src = src
        self.dest = dest
        self.ap_name = ap_name

    def get_named_mac(self, type):
        if type == "src":
            return NamedMac(self.src, self.ap_name)
        elif type == "dest":
            return NamedMac(self.dest, self.ap_name)
        else:
            raise Exception("Undefined type")


class NamedMac:
    def __init__(self, mac=Optional[str], name=Optional[str]):
        self.mac = mac
        self.name = name
