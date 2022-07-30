from pyvis.network import Network
from scapy.all import *
from scapy.layers.dot11 import Dot11Elt

from Packet import Packet as FuoPacket

net = Network()

# net.show_buttons(filter_=True)
net.toggle_physics(True)

pcap_path = open("/Users/fuomag9/Downloads/vicinimerda2.pcap-01.cap", 'rb')
macs = {}
for packet in PcapReader(pcap_path):
    try:
        ap_name = packet[Dot11Elt].info.decode("utf-8")
    except Exception:
        ap_name = ""
    try:
        print(packet.addr1, packet.addr2, packet.addr3, packet.addr4)
        pp = FuoPacket(src=packet.addr2, dest=packet.addr1, ap_name=ap_name)
        pd = pp.get_named_mac("dest")
        ps = pp.get_named_mac("src")
        if macs.get(ps) is None and ps.mac != "ff:ff:ff:ff:ff:ff" and ps.mac is not None:
            macs[ps] = []
        if pp.dest is not None and pd.mac != "ff:ff:ff:ff:ff:ff":
            macs[ps].append(pd)
    except Exception as e:
        pass

for key in macs.keys():
    macs[key] = set(macs[key])

net.add_nodes([x.mac for x in macs.keys()], label=[x.mac + "\n" + x.name for x in macs.keys()])

for macc in macs.values():
    if macc != {None}:
        net.add_nodes([x.mac for x in macc], label=[x.mac + "\n" + x.name for x in macc])
edges = []
for key, maccc in macs.items():
    for mac in maccc:
        try:
            net.add_edge(key.mac, mac.mac)
        except Exception as e:
            pass
net.show('nodes.html')

print("a")
