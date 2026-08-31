# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import struct

from scapy.compat import raw
from scapy.layers.inet6 import IPv6
from scapy.layers.ipsec import ESP, SecurityAssociation

from config import *

# What ESP adds around the encrypted part, for the length arithmetic below
esp_iv_len = 8
esp_icv_len = 16
esp_block_size = 4
# What the ESP trailer's next-header byte is allowed to say, since the only thing dp-service
# tunnels is an IP packet
esp_tunneled_protos = (4, 41)


# The neighbouring dp-service instance, as far as this test suite is concerned.
#
# Every other test plays the underlay fabric by reflecting captured bytes back. That stops
# working once the two directions carry different keys: what goes back has to be *built*, not
# echoed. Which is the point - a peer that only echoes proves dp-service can be read, never that
# it accepts a frame it did not produce itself.
#
# One instance serves the whole test session, see the ipsec_peer fixture. The sequence numbers
# live inside the SecurityAssociation objects and dp-service's associations live for as long as
# the process does, so a peer rebuilt per test would start counting from 1 again and look like a
# replayer to any anti-replay window.
class IpsecPeer:

	def __init__(self):
		self.egress = self._sa(ipsec_key_egress, ipsec_salt_egress)
		self.ingress = self._sa(ipsec_key_ingress, ipsec_salt_ingress)
		# Identical to the ingress association in every respect but the key, so that a frame
		# built with it differs from a good one only in its ICV
		self.unauthorized = self._sa(ipsec_key_wrong, ipsec_salt_ingress)

	@staticmethod
	def _sa(key, salt):
		# scapy's AES-GCM expects the key and the salt concatenated, exactly as RFC 4106 defines
		return SecurityAssociation(ESP, spi=ipsec_spi, crypt_algo="AES-GCM",
								   crypt_key=bytes.fromhex(key) + bytes.fromhex(salt))

	# Read a frame dp-service encrypted, returning the outer IPv6 packet with ESP taken back out,
	# which is precisely what ipip_encap produced before ipsec_encap ran.
	def decrypt(self, pkt):
		# on a copy, because scapy's decrypt() rewrites the packet it is given
		return self.egress.decrypt(pkt[IPv6].copy())

	# Build a frame for dp-service to decrypt, out of such an outer IPv6 packet
	def encrypt(self, pkt):
		return self.ingress.encrypt(pkt)

	# The same frame, authenticated with key material dp-service was never given.
	# It has to keep advancing the *ingress* sequence numbers: a second association counting from
	# 1 of its own would be rejected by the anti-replay window before its ICV was ever looked at,
	# and a test asserting the frame is dropped would then pass for entirely the wrong reason.
	def encrypt_with_wrong_key(self, pkt):
		self.unauthorized.seq_num = self.ingress.seq_num
		frame = self.unauthorized.encrypt(pkt)
		self.ingress.seq_num = self.unauthorized.seq_num
		return frame


# Assertions on the framing itself, on top of what decrypting the frame already proves.
# scapy's decrypt() verifies the ICV and the trailer length, but it does not check how the
# explicit IV was derived, and it cannot report the padding bytes at all - its own padding slice
# is taken from an already-truncated buffer (scapy 2.5.0). So what is checked here is what a
# successful decrypt would silently accept.
def assert_esp_framing(esp, decrypted):
	# The sequence number doubles as the explicit nonce. That is what makes a repeated GCM nonce
	# under one key impossible by construction rather than merely unlikely, and it is the single
	# most dangerous thing about this cipher, so it does not get to rest on a comment.
	assert esp.data[:esp_iv_len] == struct.pack(">Q", esp.seq), \
		"Explicit IV is not the sequence number"

	crypt_len = len(esp.data) - esp_iv_len - esp_icv_len
	assert crypt_len % esp_block_size == 0, \
		"Encrypted part of the frame is not 4-byte aligned"

	# the trailer has to start as early as that alignment allows, i.e. no gratuitous padding
	payload_len = len(raw(decrypted.payload))
	assert crypt_len - payload_len - 2 == -(payload_len + 2) % esp_block_size, \
		"Encrypted part of the frame is padded to the wrong length"

	assert decrypted.nh in esp_tunneled_protos, \
		"ESP trailer does not name a tunneled IP packet"
