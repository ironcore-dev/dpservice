# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

from helpers import *

def test_l2_arp(prepare_ifaces):
	arp_packet = (Ether(dst="ff:ff:ff:ff:ff:ff") /
				  ARP(pdst=gateway_ip, hwdst=VM1.mac, psrc="0.0.0.0"))
	answer, unanswered = srp(arp_packet, iface=VM1.tap, type=ETH_P_ARP, timeout=sniff_timeout)
	assert len(answer) == 1, \
		"No ARP response"
	for sent, received in answer:
		src_mac = received[ARP].hwsrc
		assert src_mac == VM1.mac, \
			f"Bad ARP response (source mac: {src_mac})"
