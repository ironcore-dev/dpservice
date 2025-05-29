# SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import pytest

from config import *
from helpers import *


def local_vf_to_vf_responder(vm):
	pkt = sniff_packet(vm.tap, is_udp_pkt)
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x0800) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport))
	# Send it back to the other dpservice
	delayed_sendp(reply_pkt, vm.tap_b)

def test_ha_vm_vm_local(prepare_ifaces, prepare_ifaces_b):
	threading.Thread(target=local_vf_to_vf_responder, args=(VM2,)).start()

	pkt = (Ether(dst=VM2.mac, src=VM1.mac, type=0x0800) /
			IP(dst=VM2.ip, src=VM1.ip) /
			UDP(dport=1234))
	delayed_sendp(pkt, VM1.tap)

	# Sniff the other dpservice
	sniff_packet(VM1.tap_b, is_udp_pkt)


def cross_vf_to_vf_responder(pf, dst_vm):
	pkt = sniff_packet(pf.tap, is_udp_pkt)
	assert pkt[IPv6].src == dst_vm.ul_ipv6, \
		"Packet not from the right VM"
	# Send it back to the other dpservice (different underlay address)
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=dst_vm.ul_ipv6_b, src=pkt[IPv6].dst) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport))
	delayed_sendp(reply_pkt, pf.tap_b)

def test_ha_vm_vm_cross(prepare_ifaces, prepare_ifaces_b):
	threading.Thread(target=cross_vf_to_vf_responder, args=(PF0, VM1)).start()

	pkt = (Ether(dst=PF0.mac, src=VM1.mac, type=0x0800) /
			IP(dst=f"{neigh_vni1_ov_ip_prefix}.1", src=VM1.ip) /
			UDP(dport=1234))
	delayed_sendp(pkt, VM1.tap)

	# Sniff the other dpservice
	sniff_packet(VM1.tap_b, is_udp_pkt)


# This is essentially the same as cross-VM-VM communication
# (in reality this packet gets dropped on the way out to the internet)
def test_ha_vm_public(prepare_ifaces, prepare_ifaces_b):
	threading.Thread(target=cross_vf_to_vf_responder, args=(PF0, VM1)).start()

	pkt = (Ether(dst=PF0.mac, src=VM1.mac, type=0x0800) /
			IP(dst=public_ip, src=VM1.ip) /
			UDP(dport=1234))
	delayed_sendp(pkt, VM1.tap)

	# Sniff the other dpservice
	sniff_packet(VM1.tap_b, is_udp_pkt)

# TODO test vip? maybe it will work?

# TODO test LB maglev - should still work

# TODO test LB using the other one - should fail?

# TODO test NAT reply to the other one - should fail

# TODO others? like private LB, LB-NAT, LB-VIP, etc?

# TODO packet relay!
