from helpers import *


def test_l2_arp(add_machine):
	arp_packet = (Ether(dst=bcast_mac) /
				  ARP(pdst=gw_ip4, hwdst=vf0_mac, psrc=null_ip))
	answer, unanswered = srp(arp_packet, iface=vf0_tap, type=ETH_P_ARP, timeout=2)
	for sent, received in answer:
		assert str(received[ARP].hwsrc) == vf0_mac
