# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import threading

import pytest

from helpers import *
from ipsec_peer import IpsecPeer, assert_esp_framing

# A full rotation of both directions of one tunnel, with the packet count as the proof that no
# step of it has a gap.
#
# The two halves rotate differently, which is the shape of the whole design. An egress association
# is found under the VNI it serves, so a second one for that VNI and peer is the same database
# entry rather than a second slot: it is *replaced*, in one request, and dpservice swaps the
# replacement in between two packets. An ingress association is found under the SPI its frames
# carry, so several of them coexist: it is rotated by adding the new one beside the live one and
# deleting the old one once the peer has switched. See docs/adr/0006.
#
# The order matters and is the control plane's to get right, because dpservice cannot see whether
# the peer is ready: the receiver installs what it needs *before* the sender starts using it. That
# is what this file runs - the receiver adds the new egress key first, and the old ingress
# association is deleted last.
#
# There is no race to observe here and none is attempted. gRPC requests are processed by
# rx_periodic, a source node of the one graph, so no packet is handled while a replacement is
# swapped in; what a burst on either side of it demonstrates is that the transition costs nothing.

udp_sport = 1234
udp_dport = 12345
neigh_ov_ip = f"{neigh_vni1_ov_ip_prefix}.148"


def burst_payloads(tag):
	# distinct per burst, so that a packet left over from an earlier one cannot satisfy a later
	# assertion
	return [f"rekey {tag} {i}".encode() for i in range(1, 4)]

def is_test_udp_pkt(pkt):
	return UDP in pkt and pkt[UDP].dport == udp_dport

def get_udp_payload(pkt):
	# Slice by the UDP length field, otherwise ethernet padding would be counted in
	return raw(pkt[UDP])[8:pkt[UDP].len]


# The peer as it goes through a rotation.
#
# It holds every egress association dpservice might be sending under - the one being replaced and
# the one replacing it - and picks by the SPI it reads off the frame, which is exactly what a
# receiver does while both are in play. Being told which key to use instead would let this file
# pass without ever showing that the SPI on the wire changed.
#
# The reply direction starts as the session's own peer object rather than a fresh association,
# because dpservice's ingress association keeps its anti-replay window and its history for the
# life of the process: a second association counting from 1 of its own would be refused as a
# replay. Only once *that* association has been replaced by one of its own can the peer count
# from 1 again, which is what switch_ingress() does.
class RekeyPeer:

	def __init__(self, peer):
		self.peer = peer
		self.egress_sas = {}
		self.reply_sa = None

	# an association dpservice may start sending under, added before it is told to
	def add_egress(self, spi, key, salt):
		self.egress_sas[spi] = IpsecPeer._sa(spi, key, salt)

	# the association the peer answers with from here on, added to dpservice beforehand
	def switch_ingress(self, spi, key, salt):
		self.reply_sa = IpsecPeer._sa(spi, key, salt)

	def decrypt(self, pkt):
		sa = self.egress_sas.get(pkt[ESP].spi)
		if sa is None:
			assert pkt[ESP].spi == ipsec_spi_egress, \
				f"Frame carries an SPI no association was provisioned for ({pkt[ESP].spi:#x})"
			return self.peer.decrypt(pkt)
		return sa.decrypt(pkt[IPv6].copy())

	def encrypt(self, pkt):
		if self.reply_sa is None:
			return self.peer.encrypt(pkt)
		return self.reply_sa.encrypt(pkt)


def encrypted_loopback_responder(pf_tap, peer, payloads, seen):
	pkts = sniff_packets(pf_tap, is_esp_pkt, len(payloads))
	loop_pkts = []
	for pkt, payload in zip(pkts, payloads):
		assert pkt[IPv6].dst == neigh_vni1_ul_ipv6, \
			"Invalid destination in encaped request"
		assert payload not in raw(pkt), \
			"Payload is readable in the encrypted request"
		tunneled = peer.decrypt(pkt)
		assert IP in tunneled and UDP in tunneled[IP], \
			"Decrypted request does not carry the tunneled IPv4 packet"
		assert get_udp_payload(tunneled[IP]) == payload, \
			"Decrypted request carries the wrong payload"
		assert_esp_framing(pkt[ESP], tunneled)
		seen.append((pkt[ESP].spi, pkt[ESP].seq))
		# answer the way the peer would, with whichever association it is answering under now
		tunneled.src, tunneled.dst = tunneled.dst, VM2.ul_ipv6
		reply = peer.encrypt(tunneled)
		loop_pkts.append(Ether(dst=pkt[Ether].src, src=pkt[Ether].dst) / reply)
	delayed_sendp(loop_pkts, pf_tap)


# One burst there and back: VM1 to the neighbouring instance, encrypted on the PF, decrypted and
# answered by the peer, delivered to VM2. Returns the SPI and sequence number of every frame that
# was on the wire, and joins the responder before it does - nothing of one burst is still in
# flight when the next association change happens.
def assert_burst(peer, tag):
	payloads = burst_payloads(tag)
	seen = []
	responder = threading.Thread(target=encrypted_loopback_responder,
								 args=(PF0.tap, peer, payloads, seen))
	responder.start()

	udp_pkts = [Ether(dst=PF0.mac, src=VM1.mac) /
				IP(dst=neigh_ov_ip, src=VM1.ip) /
				UDP(sport=udp_sport, dport=udp_dport) /
				Raw(payload)
				for payload in payloads]
	delayed_sendp(udp_pkts, VM1.tap)

	pkts = sniff_packets(VM2.tap, is_test_udp_pkt, len(payloads))
	for pkt, payload in zip(pkts, payloads):
		assert pkt[IP].src == VM1.ip and pkt[IP].dst == neigh_ov_ip, \
			f"Wrong packet received (src ip: {pkt[IP].src}, dst ip: {pkt[IP].dst})"
		assert get_udp_payload(pkt) == payload, \
			"Payload damaged by the round trip"

	responder.join()
	assert len(seen) == len(payloads), \
		"Not every packet was encrypted onto the PF"
	return seen


# Put the pair dp_service.py installed back, however the test ended: the package-scoped IpsecPeer
# and everything running after this file hold the original key material.
#
# The egress half goes back the way it came, by replacement. It does put a key back into service
# with a sequence number starting over, which is the one thing a deployment must not do - safe
# here only because the peer is scapy, which has no window to fool and no adversary to fool it.
def restore_associations(grpc_client):
	grpc_client.updatesa(vni1, ipsec_spi_rekeyed_egress, "egress", local_ul_ipv6, neigh_vni1_ul_ipv6,
						 ipsec_spi_egress, ipsec_key_egress, ipsec_salt_egress)
	grpc_client.addsa(vni1, ipsec_spi_ingress, "ingress", neigh_vni1_ul_ipv6, local_ul_ipv6,
					  ipsec_key_ingress, ipsec_salt_ingress, replay_window=ipsec_replay_window)
	grpc_client.delsa(vni1, ipsec_spi_rekeyed_ingress, "ingress", neigh_vni1_ul_ipv6, local_ul_ipv6)


def test_ipsec_rekey_both_directions(prepare_ipv4, grpc_client, ipsec_peer):
	peer = RekeyPeer(ipsec_peer)
	try:
		# Everything on the pair the session was set up with
		seen = assert_burst(peer, "before")
		assert all(spi == ipsec_spi_egress for spi, _ in seen), \
			"Traffic did not start out on the association dp_service.py installed"

		# The receiver goes first, because dpservice cannot tell whether it is ready. Both of its
		# egress associations are live from here on, and it picks by the SPI on the frame.
		peer.add_egress(ipsec_spi_rekeyed_egress, ipsec_key_rekeyed_egress, ipsec_salt_rekeyed_egress)

		# One request, and the outbound association is a different one - no delete, no gap
		grpc_client.updatesa(vni1, ipsec_spi_egress, "egress", local_ul_ipv6, neigh_vni1_ul_ipv6,
							 ipsec_spi_rekeyed_egress, ipsec_key_rekeyed_egress, ipsec_salt_rekeyed_egress)
		sa = grpc_client.getsa(vni1, ipsec_spi_rekeyed_egress, "egress", local_ul_ipv6, neigh_vni1_ul_ipv6)
		assert sa['key'] == ipsec_key_rekeyed_egress and sa['salt'] == ipsec_salt_rekeyed_egress, \
			"Egress association was not replaced with the key material asked for"
		# the association is still filed under its VNI, but it is no longer the one that was named
		grpc_client.expect_error(462).getsa(vni1, ipsec_spi_egress, "egress", local_ul_ipv6, neigh_vni1_ul_ipv6)

		# Outbound on the replacement, inbound untouched: the peer keeps answering under the
		# association - and the sequence number - it has been using all along
		seen = assert_burst(peer, "outbound")
		assert all(spi == ipsec_spi_rekeyed_egress for spi, _ in seen), \
			"Traffic did not move onto the association that replaced it"
		assert seen[0][1] == 1, \
			"The replacement did not start a sequence number of its own"

		# The inbound half, which is not a replacement: the new association is added beside the
		# live one, both serve this VNI and peer at once, and only once the sender has switched is
		# the old one deleted. That the peer can count from 1 again is the whole point - it is a
		# different association, with a window of its own.
		grpc_client.addsa(vni1, ipsec_spi_rekeyed_ingress, "ingress", neigh_vni1_ul_ipv6, local_ul_ipv6,
						  ipsec_key_rekeyed_ingress, ipsec_salt_rekeyed_ingress,
						  replay_window=ipsec_replay_window)
		peer.switch_ingress(ipsec_spi_rekeyed_ingress, ipsec_key_rekeyed_ingress, ipsec_salt_rekeyed_ingress)
		grpc_client.delsa(vni1, ipsec_spi_ingress, "ingress", neigh_vni1_ul_ipv6, local_ul_ipv6)

		# Both directions now on key material the tunnel did not start with, nine packets sent and
		# nine delivered across the whole rotation
		seen = assert_burst(peer, "after")
		assert all(spi == ipsec_spi_rekeyed_egress for spi, _ in seen), \
			"Outbound traffic left the association it was rekeyed onto"
	finally:
		restore_associations(grpc_client)
