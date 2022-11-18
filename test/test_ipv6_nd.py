from scapy.all import *

from config import *

def test_nd(add_machine):
	answer = neighsol(gw_ip6, vf0_ipv6, iface=vf0_tap, timeout=2)
	mac = str(answer[ICMPv6NDOptDstLLAddr].lladdr)
	print(mac)
	assert mac == vf0_mac
