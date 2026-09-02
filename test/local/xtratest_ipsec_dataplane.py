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

def assert_delivered(frame, message):
	assert len(inject(frame, sniff_timeout)) == 1, message

# The short timeout is what makes this affordable: a frame that is going to arrive has already
# arrived by then, and one that never will costs only that wait.
def assert_dropped(frame, message):
	assert len(inject(frame, sniff_short_timeout)) == 0, message


def test_ipsec_bad_icv_is_dropped(prepare_ipv4, ipsec_peer):
	# first the frame as it should be, so that everything except the key is known to be right
	assert len(inject(build_frame(ipsec_peer.encrypt), sniff_timeout)) == 1, \
		"Correctly authenticated frame was not delivered"

	# then the very same frame, authenticated with a key dpservice was never given
	assert len(inject(build_frame(ipsec_peer.encrypt_with_wrong_key), sniff_short_timeout)) == 0, \
		"Frame with an invalid ICV was decrypted and delivered"


# What the anti-replay window is for. dp_service.py creates the session's ingress association with
# a 64-packet window, and until this test nothing asserted that the window does anything at all -
# every frame the peer builds carries a fresh, increasing sequence number, so the branch in
# ipsec_decap that reports the window rejecting one was unreachable from the suite.
#
# The three sequence numbers below are placed relative to where the peer happens to be, because
# how many frames earlier tests sent is not this test's business. Sending one at n+200 first is
# what makes the rest deterministic: it drags dpservice's window up to a known edge, whatever the
# window had seen before.
def test_ipsec_replay_is_dropped(prepare_ipv4, ipsec_peer):
	base = ipsec_peer.next_seq()

	# the ordinary case first, so that a frame failing later cannot be blamed on how it is built
	frame = build_frame(ipsec_peer.encrypt)
	assert_delivered(frame, "Frame with a fresh sequence number was not delivered")

	# the very same bytes a second time
	assert_dropped(frame, "Replayed frame was decrypted and delivered")

	# jumping ahead is legitimate - the underlay may lose frames - and slides the window up
	assert_delivered(build_frame(lambda pkt: ipsec_peer.encrypt_at_seq(pkt, base + 200)),
					 "Frame ahead of the window was not delivered")

	# 100 behind the edge of a 64-packet window, so too old to be judged
	assert_dropped(build_frame(lambda pkt: ipsec_peer.encrypt_at_seq(pkt, base + 100)),
				   "Frame below the window was decrypted and delivered")

	# 20 behind the edge and never seen, which is exactly what the window exists to accept. Without
	# this assertion an implementation that merely demanded increasing sequence numbers would pass
	# every line above, while silently dropping traffic the underlay had reordered.
	assert_delivered(build_frame(lambda pkt: ipsec_peer.encrypt_at_seq(pkt, base + 180)),
					 "Reordered frame inside the window was not delivered")

	# leaving the peer past everything used here, see IpsecPeer.advance_seq_to()
	ipsec_peer.advance_seq_to(base + 201)


# The mirror image, on an association created without the field at all: dpservice defaults the
# window to zero and zero means no replay checking whatsoever, so the frame that was dropped above
# is delivered twice here. See docs/adr/0002-anti-replay-disabled-by-default.md.
#
# The association is created here rather than in dp_service.py, which describes underlay topology;
# an association with anti-replay switched off exists for this test and nothing else.
def test_ipsec_replay_without_window(prepare_ipv4, grpc_client, ipsec_peer):
	# no --replay-window, so what is being tested is the default a client gets by omitting it
	grpc_client.addsa(ipsec_spi_unwindowed, "ingress", neigh_vni1_ul_ipv6, local_ul_ipv6,
					  ipsec_key_unwindowed, ipsec_salt_unwindowed)

	assert grpc_client.getsa(ipsec_spi_unwindowed, neigh_vni1_ul_ipv6, local_ul_ipv6)['replay_window'] == 0, \
		"Association created without a replay window did not default to none"

	try:
		frame = build_frame(ipsec_peer.encrypt_unwindowed)
		assert_delivered(frame, "Frame on an unwindowed association was not delivered")
		assert_delivered(frame, "Replayed frame was dropped by an association with no window")
	finally:
		grpc_client.delsa(ipsec_spi_unwindowed, neigh_vni1_ul_ipv6, local_ul_ipv6)


# Extended sequence numbers (RFC 4304). The association counts to 2^64 rather than 2^32, but only
# the lower half is carried in the packet - the upper half is authenticated along with it and
# never sent. So the two ends cannot merely disagree about it and go on working: an association
# with ESN on and one with it off compute their ICV over different bytes.
#
# That is exactly what makes it testable without sending four billion frames. The second frame
# below is built by the same code, with the same key, the same salt, the same SPI and a sequence
# number the window has never seen; the *only* thing that differs is whether the upper half of
# that number was authenticated. If dpservice were ignoring the ESN flag, both would arrive.
#
# The association is created here rather than in dp_service.py for the reason given above
# test_ipsec_replay_without_window(): it exists for this test and nothing else.
def test_ipsec_esn_round_trip(prepare_ipv4, grpc_client, ipsec_peer):
	grpc_client.addsa(ipsec_spi_esn, "ingress", neigh_vni1_ul_ipv6, local_ul_ipv6,
					  ipsec_key_esn, ipsec_salt_esn,
					  replay_window=ipsec_replay_window, esn=True)

	assert grpc_client.getsa(ipsec_spi_esn, neigh_vni1_ul_ipv6, local_ul_ipv6)['esn'] is True, \
		"Association created with --esn did not come back carrying it"

	try:
		assert_delivered(build_frame(ipsec_peer.encrypt_esn),
						 "Frame with extended sequence numbers was not delivered")

		# the same association, the same key, a fresh sequence number - and four fewer bytes of
		# authenticated data
		assert_dropped(build_frame(ipsec_peer.encrypt_esn_disabled),
					   "Frame without extended sequence numbers was accepted by an ESN association")

		# and back to a well-formed one, so that the failure above is known to have been the
		# framing rather than something the association never recovered from
		assert_delivered(build_frame(ipsec_peer.encrypt_esn),
						 "ESN association stopped accepting frames after refusing one")
	finally:
		grpc_client.delsa(ipsec_spi_esn, neigh_vni1_ul_ipv6, local_ul_ipv6)


# The second cipher. Nothing about AES-256-GCM is visible on the wire - same nonce construction,
# same 16-byte ICV, same framing - so what this proves is narrow and worth stating: that a
# 256-bit key is carried through the gRPC layer, the algorithm table and the crypto session
# without being truncated to the 128 bits every other association in this suite uses.
#
# A truncating bug would fail here rather than silently encrypt with half a key, because the peer
# authenticates with all 32 bytes.
def test_ipsec_aes256_round_trip(prepare_ipv4, grpc_client, ipsec_peer):
	grpc_client.addsa(ipsec_spi_aes256, "ingress", neigh_vni1_ul_ipv6, local_ul_ipv6,
					  ipsec_key_aes256, ipsec_salt_aes256,
					  algorithm="aes-256-gcm", replay_window=ipsec_replay_window)

	sa = grpc_client.getsa(ipsec_spi_aes256, neigh_vni1_ul_ipv6, local_ul_ipv6)
	assert sa['algorithm'] == "aes_256_gcm", \
		"Association created with --algorithm=aes-256-gcm came back as something else"
	assert sa['key'] == ipsec_key_aes256, \
		"256-bit key did not survive the round trip through the gRPC layer"

	try:
		assert_delivered(build_frame(ipsec_peer.encrypt_aes256),
						 "Frame encrypted with a 256-bit key was not delivered")
	finally:
		grpc_client.delsa(ipsec_spi_aes256, neigh_vni1_ul_ipv6, local_ul_ipv6)
