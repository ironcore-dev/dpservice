from helpers import *


def test_l2_arp(prepare_ifaces):
	arp_packet = (Ether(dst="ff:ff:ff:ff:ff:ff") /
				  ARP(pdst=gateway_ip, hwdst=vf0_mac, psrc="0.0.0.0"))
	answer, unanswered = srp(arp_packet, iface=vf0_tap, type=ETH_P_ARP, timeout=sniff_timeout)
	assert len(answer) == 1, \
		"No ARP response"
	for sent, received in answer:
		src_mac = received[ARP].hwsrc
		assert src_mac == vf0_mac, \
			f"Bad ARP response (source mac: {src_mac})"
