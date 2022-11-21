from helpers import *


def test_nd(add_machine):
	answer = neighsol(gw_ip6, vf0_ipv6, iface=vf0_tap, timeout=2)
	lladdr = answer[ICMPv6NDOptDstLLAddr].lladdr
	assert lladdr == vf0_mac, \
		f"Wrong neighbor link-level address ({lladdr})"
