from helpers import *


def test_l2_arp(prepare_ifaces):
	arp_packet = (Ether(dst=bcast_mac) /
				  ARP(pdst=gw_ip4, hwdst=vf0_mac, psrc=null_ip))
	answer, unanswered = srp(arp_packet, iface=vf0_tap, type=ETH_P_ARP, timeout=2)
	assert len(answer) == 1, \
		"No ARP response"
	for sent, received in answer:
		src_mac = received[ARP].hwsrc
		assert src_mac == vf0_mac, \
			f"Bad ARP response (source mac: {src_mac})"
