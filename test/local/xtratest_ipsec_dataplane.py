# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import threading

from helpers import *

# test_vf_to_vf_encap.py proves the happy path in both directions. What it cannot prove is that a
# frame failing authentication is refused, because every frame it feeds dpservice is one the
# harness built with the right key - an ipsec_decap that had stopped checking the ICV entirely
# would leave that test green.
#
# This is the case that only became testable once the two directions carried different keys.
#
# The very same frame is injected twice, and the two injections differ in exactly one thing: the
# key it is authenticated with. The selectors, the SPI, the outer and inner addresses and the
# code that builds it are all shared, so the second one failing to arrive cannot be blamed on a
# malformed packet - which is what the first injection establishes.

# what ipip_encap tunnels IPv4 in, and what the ESP trailer therefore has to name
ipip_proto = 4

udp_sport = 1234
udp_dport = 12345
udp_payload = b"icv check"
neigh_ov_ip = f"{neigh_vni1_ov_ip_prefix}.147"


def is_test_udp_pkt(pkt):
	return UDP in pkt and pkt[UDP].dport == udp_dport


# A tunneled packet bound for VM2, framed the way the peer frames the ones it sends back. The
# outer destination alone picks the target port, ipip_decap never inspects the tunneled packet.
def build_frame(encrypt):
	tunneled = (IPv6(src=neigh_vni1_ul_ipv6, dst=VM2.ul_ipv6, nh=ipip_proto) /
				IP(dst=neigh_ov_ip, src=VM1.ip) /
				UDP(sport=udp_sport, dport=udp_dport) /
				Raw(udp_payload))
	return Ether(dst=PF0.mac, src=PF0.mac) / encrypt(tunneled)

def inject(frame, timeout):
	# sending from a thread, so that the sniff below is already listening when the packet lands
	threading.Thread(target=delayed_sendp, args=(frame, PF0.tap)).start()
	return sniff(count=1, lfilter=is_test_udp_pkt, iface=VM2.tap, timeout=timeout)


def test_ipsec_bad_icv_is_dropped(prepare_ipv4, ipsec_peer):
	# first the frame as it should be, so that everything except the key is known to be right
	assert len(inject(build_frame(ipsec_peer.encrypt), sniff_timeout)) == 1, \
		"Correctly authenticated frame was not delivered"

	# then the very same frame, authenticated with a key dpservice was never given
	assert len(inject(build_frame(ipsec_peer.encrypt_with_wrong_key), sniff_short_timeout)) == 0, \
		"Frame with an invalid ICV was decrypted and delivered"
