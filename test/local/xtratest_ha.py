# SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import pytest

from config import *
from helpers import *


def vf_to_vf_responder(vm):
	pkt = sniff_packet(vm.tap, is_udp_pkt)
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x0800) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport))
	# Send it back to the other dpservice
	delayed_sendp(reply_pkt, vm.tap_b)


def test_ha_vm_vm(prepare_ifaces, prepare_ifaces_b):
	threading.Thread(target=vf_to_vf_responder, args=(VM2,)).start()

	pkt = (Ether(dst=VM2.mac, src=VM1.mac, type=0x0800) /
			IP(dst=VM2.ip, src=VM1.ip) /
			UDP(dport=1234))
	delayed_sendp(pkt, VM1.tap)

	# Sniff the other dpservice
	sniff_packet(VM1.tap_b, is_udp_pkt)
