# SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import pytest

from config import *
from helpers import *


# Just a dummy responder (dummy service) on the VM
def vm_responder(dst_tap):
	pkt = sniff_packet(dst_tap, is_udp_pkt)
	assert pkt[IP].dst == lb_ip and pkt[UDP].dport == 1234, \
		"Invalid packet routed to target"
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x0800) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport))
	delayed_sendp(reply_pkt, dst_tap)


def test_conntrack_poison(prepare_ifaces, grpc_client):

	# VM-initiated traffic beforehand
	poison_pkt = (Ether(dst=VM1.mac, src=VM1.mac, type=0x0800) /
				  IP(dst=public_ip, src=lb_ip) /
				  UDP(sport=1234))
	# COMMENT THIS and the test will not fail
	delayed_sendp(poison_pkt, VM1.tap)
	# public_ip is now poisoned

	# Standard LB with one target
	lb_ul = grpc_client.createlb(lb_name, vni1, lb_ip, "udp/1234")
	lbpfx_ul = grpc_client.addlbprefix(VM2.name, lb_pfx)
	grpc_client.addlbtarget(lb_name, lbpfx_ul)

	# Standard traffic from public IP to the LB
	threading.Thread(target=vm_responder, args=(VM2.tap,)).start()

	pkt = (Ether(dst=PF0.mac, src=PF0.mac, type=0x86DD) /
		   IPv6(dst=lb_ul, src=router_ul_ipv6, nh=4) /
		   IP(dst=lb_ip, src=public_ip) /
		   UDP(dport=1234))
	delayed_sendp(pkt, PF0.tap)

	reply = sniff_packet(PF0.tap, is_udp_pkt)
	assert reply[IP].dst == public_ip and reply[UDP].sport == 1234, \
		"Invalid reply from target"

	grpc_client.dellbtarget(lb_name, lbpfx_ul)
	grpc_client.dellbprefix(VM2.name, lb_pfx)
	grpc_client.dellb(lb_name)
