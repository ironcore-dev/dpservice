# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import threading

import pytest
from helpers import *

# Encryption is a property of an interface, and the whole of the policy is one statement, held
# in both directions:
#
#     cleartext leaves an interface if and only if it is not encrypting,
#     and cleartext is accepted for an interface if and only if it is not encrypting.
#
# The rest of the suite only ever runs with every interface encrypting, so it covers the left
# half of both sentences and none of the right. This file covers the right half, and the two
# refusals that make the left half mean anything: ESP arriving for a cleartext interface, and
# cleartext arriving for an encrypting one. See docs/adr/0007.
#
# Every test here puts the interfaces back the way dp_service.py created them, because the
# fixture is shared with every other file in the suite.

# what ipip_encap tunnels IPv4 in, and what a cleartext tunnel frame therefore carries
ipip_proto = 4

udp_sport = 1234
udp_dport = 12345
udp_payload = b"policy"
neigh_ov_ip = f"{neigh_vni1_ov_ip_prefix}.147"


def is_test_udp_pkt(pkt):
	return UDP in pkt and pkt[UDP].dport == udp_dport


@pytest.fixture
def cleartext_vm2(grpc_client):
	"""VM2 stops encrypting for the duration of one test, and is put back afterwards."""
	grpc_client.disableencryption(VM2.name)
	yield
	grpc_client.enableencryption(VM2.name)


@pytest.fixture
def cleartext_vm1(grpc_client):
	"""VM1 stops encrypting for the duration of one test, and is put back afterwards."""
	grpc_client.disableencryption(VM1.name)
	yield
	grpc_client.enableencryption(VM1.name)


# The tunneled packet a peer sends VM2, without the ESP framing around it. This is what
# ipip_encap would have produced on the sending side, and what ipsec_decap hands ipip_decap
# after it has taken ESP back off - so as far as ipip_decap is concerned the two are the same
# packet, and only cls can tell them apart.
def build_tunneled():
	return (IPv6(src=neigh_vni1_ul_ipv6, dst=VM2.ul_ipv6, nh=ipip_proto) /
			IP(dst=neigh_ov_ip, src=VM1.ip) /
			UDP(sport=udp_sport, dport=udp_dport) /
			Raw(udp_payload))

def build_cleartext_frame():
	return Ether(dst=PF0.mac, src=PF0.mac) / build_tunneled()

def build_esp_frame(peer):
	return Ether(dst=PF0.mac, src=PF0.mac) / peer.encrypt(build_tunneled())

def inject(frame, timeout):
	# sending from a thread, so that the sniff below is already listening when the frame lands
	threading.Thread(target=delayed_sendp, args=(frame, PF0.tap)).start()
	return sniff(count=1, lfilter=is_test_udp_pkt, iface=VM2.tap, timeout=timeout)


#
# Ingress
#

# The half of the policy that carries the weight. Without it, injecting into a protected tenant
# needs no key, no ICV and no guessed SPI - an ordinary IPinIP frame addressed at the endpoint
# would be decapsulated and delivered, and the key material would protect confidentiality only.
def test_ipsec_cleartext_for_encrypting_iface_is_dropped(prepare_ipv4, ipsec_peer):
	assert len(inject(build_esp_frame(ipsec_peer), sniff_timeout)) == 1, \
		"Encrypted frame for an encrypting interface was not delivered"

	assert len(inject(build_cleartext_frame(), sniff_short_timeout)) == 0, \
		"Cleartext frame for an encrypting interface was delivered"


# The mirror, and the one the feature request asked for. Weaker on its own - a peer holding no
# association is refused by the database anyway - but it is what makes a cleartext interface
# genuinely cleartext rather than merely willing to be.
def test_ipsec_esp_for_cleartext_iface_is_dropped(prepare_ipv4, ipsec_peer, cleartext_vm2):
	assert len(inject(build_cleartext_frame(), sniff_timeout)) == 1, \
		"Cleartext frame for a cleartext interface was not delivered"

	assert len(inject(build_esp_frame(ipsec_peer), sniff_short_timeout)) == 0, \
		"Encrypted frame for a cleartext interface was delivered"


# The two frames above are the same packet, so neither refusal can be blamed on how it is built.
# This asserts that directly: one interface, one frame, two answers, and nothing changing in
# between but the flag.
def test_ipsec_ingress_follows_the_flag(prepare_ipv4, grpc_client, ipsec_peer):
	assert len(inject(build_cleartext_frame(), sniff_short_timeout)) == 0, \
		"Cleartext frame was delivered to an encrypting interface"

	grpc_client.disableencryption(VM2.name)
	try:
		assert len(inject(build_cleartext_frame(), sniff_timeout)) == 1, \
			"The very same frame was refused after encryption was turned off"
	finally:
		grpc_client.enableencryption(VM2.name)


#
# Egress
#

# Sends one packet from VM1 towards the peer's overlay prefix and returns what left on the PF.
def send_from_vm1(lfilter):
	pkt = (Ether(dst=PF0.mac, src=VM1.mac) /
		   IP(dst=neigh_ov_ip, src=VM1.ip) /
		   UDP(sport=udp_sport, dport=udp_dport) /
		   Raw(udp_payload))
	threading.Thread(target=delayed_sendp, args=(pkt, VM1.tap)).start()
	return sniff_packet(PF0.tap, lfilter)


# A cleartext interface takes exactly the path it takes in a build without IPsec: ipip_encap
# straight to Tx, never through ipsec_encap. VM1 has an egress association the whole time, so
# this proves the flag and not the absence of key material is what decides.
def test_ipsec_cleartext_iface_sends_in_the_clear(prepare_ipv4, cleartext_vm1):
	encaped = send_from_vm1(is_encaped_udp_pkt)
	assert encaped[IPv6].dst == neigh_vni1_ul_ipv6, \
		"Cleartext tunnel packet went to the wrong underlay destination"
	assert udp_payload in raw(encaped), \
		"Payload is not readable in what should be an unencrypted tunnel packet"


# Mixed VNIs are legal and nothing validates the combination: VM1 and VM2 share vni1 and the one
# egress association filed under it, and the flag is still per interface. Both halves are
# asserted in the dataplane, not just in the API, because sharing an association is exactly what
# would make one interface's policy leak into the other's.
def test_ipsec_mixed_vni_is_allowed(prepare_ipv4, grpc_client, ipsec_peer, cleartext_vm1):
	assert grpc_client.getencryption(VM1.name) is False, \
		"VM1 is still encrypting"
	assert grpc_client.getencryption(VM2.name) is True, \
		"VM2 stopped encrypting when VM1 did, in the same VNI"

	# VM1 sends in the clear even though its VNI has an egress association...
	assert udp_payload in raw(send_from_vm1(is_encaped_udp_pkt)), \
		"Cleartext interface encrypted because another interface in its VNI does"

	# ...while VM2, on that same VNI and association, still takes only ESP
	assert len(inject(build_esp_frame(ipsec_peer), sniff_timeout)) == 1, \
		"Encrypting interface stopped accepting ESP because another interface in its VNI does not encrypt"
	assert len(inject(build_cleartext_frame(), sniff_short_timeout)) == 0, \
		"Encrypting interface accepted cleartext because another interface in its VNI does not encrypt"
