# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import pytest
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


def vm_mac_sender():
	pkt = (Ether(dst=PF0.mac, src=VM1.mac) /
		   IP(dst=VM4.ip, src=VM1.ip) /
		   UDP(dport=1234))
	delayed_sendp(pkt, VM1.tap)

def test_l2_addr_once(request, prepare_ifaces, grpc_client):
	if request.config.getoption("--hw"):
		pytest.skip("Cannot test MAC address change with real hardware")

	grpc_client.addinterface(VM4.name, VM4.pci, VM4.vni, VM4.ip, VM4.ipv6)

	# No need to use ARP/DHCP/ND, since dpservice already "guessed" the MAC from the representor

	threading.Thread(target=vm_mac_sender).start()
	pkt = sniff_packet(VM4.tap, is_udp_pkt)
	assert pkt[Ether].dst == VM4.mac, \
		"Dpservice not using reprentor MAC"

	# Now ARP/DHCP/ND happens, discovering the VM actually has a different MAC
	# (can happen on newer systemd with MACAddressPolicy != 'persistent')
	request_ip(VM4, "12:34:56:78:9a:bc")

	threading.Thread(target=vm_mac_sender).start()
	pkt = sniff_packet(VM4.tap, is_udp_pkt)
	assert pkt[Ether].dst == "12:34:56:78:9a:bc", \
		"Dpservice not using actual VM MAC"

	# Additional ARP/DHCP/ND should not be able to change MAC again
	request_ip(VM4)

	threading.Thread(target=vm_mac_sender).start()
	pkt = sniff_packet(VM4.tap, is_udp_pkt)
	assert pkt[Ether].dst == "12:34:56:78:9a:bc", \
		"Dpservice changed VM MAC"

	# Now the VM gets removed and *another one* is put into its place
	# This can have different MAC address
	grpc_client.delinterface(VM4.name)
	grpc_client.addinterface(VM4.name, VM4.pci, VM4.vni, VM4.ip, VM4.ipv6)

	# Without ARP/DHCP/ND dpservice should try the use the old MAC
	threading.Thread(target=vm_mac_sender).start()
	pkt = sniff_packet(VM4.tap, is_udp_pkt)
	assert pkt[Ether].dst == "12:34:56:78:9a:bc", \
		"Dpservice reset VM MAC"

	# Additional ARP/DHCP/ND should be able to change MAC
	# because it is the first time after installing the interface
	request_ip(VM4, "01:02:03:04:05:06")

	threading.Thread(target=vm_mac_sender).start()
	pkt = sniff_packet(VM4.tap, is_udp_pkt)
	assert pkt[Ether].dst == "01:02:03:04:05:06", \
		"Dpservice did not accept VM MAC"

	grpc_client.delinterface(VM4.name)
