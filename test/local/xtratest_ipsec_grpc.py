# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

from helpers import *

# Exercises the Security Association gRPC calls on their own, without sending a single packet,
# so that an API failure and a dataplane failure are distinguishable at a glance.
#
# These use different parameters than the associations dp_service.py installs for the
# round-trip test, because both run against the same dpservice instance and pytest orders this
# file first. Deleting the round-trip test's associations here would make it fail in a way that
# looks like a crypto bug.
sa_vni = vni2
sa_spi = 0x3344
sa_src = local_ul_ipv6
sa_dst = "fc00:3::1"
sa_key = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
sa_key_alt = "b7c4a91e60d3528f4a1c96b70e2d5834"
sa_key_256 = "0f1e2d3c4b5a69788796a5b4c3d2e1f0c3d2e1f00f1e2d3c4b5a697887960a5b"
sa_salt = "0a1b2c3d"
sa_replay_window = 64

# Only the first 64 bits are matched, so this is what dpservice stores and reports back
sa_src_prefix = "fc00:1::"
sa_dst_prefix = "fc00:3::"


def test_ipsec_sa_lifecycle(prepare_ipv4, grpc_client):
	grpc_client.addsa(sa_vni, sa_spi, "egress", sa_src, sa_dst, sa_key, sa_salt)

	sa = grpc_client.getsa(sa_vni, sa_spi, "egress", sa_src, sa_dst)
	assert sa['vni'] == sa_vni, \
		"Security Association came back with the wrong VNI"
	assert sa['spi'] == sa_spi, \
		"Security Association came back with the wrong SPI"
	assert sa['direction'] == "egress", \
		"Security Association came back with the wrong direction"
	assert sa['algorithm'] == "aes_128_gcm", \
		"Security Association came back with the wrong algorithm"
	assert sa['key'] == sa_key and sa['salt'] == sa_salt, \
		"Security Association came back with the wrong key material"
	# the addresses are stored masked, which is what is actually matched per packet
	assert sa['src_underlay'] == sa_src_prefix and sa['dst_underlay'] == sa_dst_prefix, \
		"Security Association is not matched on the first 64 bits of the addresses"

	grpc_client.delsa(sa_vni, sa_spi, "egress", sa_src, sa_dst)

	grpc_client.expect_error(462).getsa(sa_vni, sa_spi, "egress", sa_src, sa_dst)

# The address pair is a part of the identity, so the very same VNI, SPI and key is a different
# association in the other direction
def test_ipsec_sa_mirrored_directions(prepare_ipv4, grpc_client):
	grpc_client.addsa(sa_vni, sa_spi, "egress", sa_src, sa_dst, sa_key, sa_salt)
	grpc_client.addsa(sa_vni, sa_spi, "ingress", sa_dst, sa_src, sa_key, sa_salt,
					  replay_window=sa_replay_window)

	assert grpc_client.getsa(sa_vni, sa_spi, "egress", sa_src, sa_dst)['direction'] == "egress", \
		"Egress association not found under its own identity"
	assert grpc_client.getsa(sa_vni, sa_spi, "ingress", sa_dst, sa_src)['direction'] == "ingress", \
		"Ingress association not found under its own identity"
	# the window is a property of the one direction that has one, so it is asserted here rather
	# than in the lifecycle test above, whose association is an egress one
	assert grpc_client.getsa(sa_vni, sa_spi, "ingress", sa_dst, sa_src)['replay_window'] == sa_replay_window, \
		"Ingress association came back with the wrong replay window"
	assert grpc_client.getsa(sa_vni, sa_spi, "egress", sa_src, sa_dst)['replay_window'] == 0, \
		"Egress association came back carrying a replay window"

	grpc_client.delsa(sa_vni, sa_spi, "egress", sa_src, sa_dst)
	grpc_client.delsa(sa_vni, sa_spi, "ingress", sa_dst, sa_src)

# All five fields name the association and all five are matched, even though only some of them
# are what it is filed under - the VNI for an egress association, the SPI for an ingress one.
# A caller working from a stale field has to find nothing, rather than the entry that happens to
# share the part it got right. See docs/adr/0004.
def test_ipsec_sa_identity_is_verified(prepare_ipv4, grpc_client):
	grpc_client.addsa(sa_vni, sa_spi, "egress", sa_src, sa_dst, sa_key, sa_salt)
	grpc_client.addsa(sa_vni, sa_spi, "ingress", sa_dst, sa_src, sa_key, sa_salt,
					  replay_window=sa_replay_window)

	# the egress association is filed under its VNI, so a stale SPI reaches it and is refused
	grpc_client.expect_error(462).getsa(sa_vni, sa_spi + 1, "egress", sa_src, sa_dst)
	grpc_client.expect_error(462).delsa(sa_vni, sa_spi + 1, "egress", sa_src, sa_dst)
	# ...and the ingress one under its SPI, so a wrong VNI reaches that one and is refused too
	grpc_client.expect_error(462).getsa(sa_vni + 1, sa_spi, "ingress", sa_dst, sa_src)
	grpc_client.expect_error(462).delsa(sa_vni + 1, sa_spi, "ingress", sa_dst, sa_src)
	# a wrong direction names neither of them
	grpc_client.expect_error(462).getsa(sa_vni, sa_spi, "ingress", sa_src, sa_dst)

	# and none of that removed or hid anything
	assert grpc_client.getsa(sa_vni, sa_spi, "egress", sa_src, sa_dst)['direction'] == "egress", \
		"A call naming the egress association by a stale SPI disturbed it"
	assert grpc_client.getsa(sa_vni, sa_spi, "ingress", sa_dst, sa_src)['direction'] == "ingress", \
		"A call naming the ingress association by a wrong VNI disturbed it"

	grpc_client.delsa(sa_vni, sa_spi, "egress", sa_src, sa_dst)
	grpc_client.delsa(sa_vni, sa_spi, "ingress", sa_dst, sa_src)

# What separating the two SPIs is for. An ingress association is filed under the SPI its frames
# carry, so several of them can serve one VNI and one peer at once - which is what installing a
# new key before retiring the old one needs. The egress side cannot, because it is filed under
# the VNI; freeing its wire SPI does not give it a second slot.
def test_ipsec_sa_coexistence(prepare_ipv4, grpc_client):
	grpc_client.addsa(sa_vni, sa_spi, "ingress", sa_dst, sa_src, sa_key, sa_salt)
	grpc_client.addsa(sa_vni, sa_spi + 1, "ingress", sa_dst, sa_src, sa_key_alt, sa_salt)

	assert grpc_client.getsa(sa_vni, sa_spi, "ingress", sa_dst, sa_src)['key'] == sa_key, \
		"The second ingress association displaced the first"
	assert grpc_client.getsa(sa_vni, sa_spi + 1, "ingress", sa_dst, sa_src)['key'] == sa_key_alt, \
		"Two ingress associations on one VNI and peer cannot coexist"

	grpc_client.delsa(sa_vni, sa_spi, "ingress", sa_dst, sa_src)
	grpc_client.delsa(sa_vni, sa_spi + 1, "ingress", sa_dst, sa_src)

	grpc_client.addsa(sa_vni, sa_spi, "egress", sa_src, sa_dst, sa_key, sa_salt)
	grpc_client.expect_error(461).addsa(sa_vni, sa_spi + 1, "egress", sa_src, sa_dst,
										sa_key_alt, sa_salt)
	grpc_client.delsa(sa_vni, sa_spi, "egress", sa_src, sa_dst)

def test_ipsec_sa_errors(prepare_ipv4, grpc_client):
	grpc_client.addsa(sa_vni, sa_spi, "egress", sa_src, sa_dst, sa_key, sa_salt)

	# a second create would otherwise silently replace the association and leak the old one
	grpc_client.expect_error(461).addsa(sa_vni, sa_spi, "egress", sa_src, sa_dst, sa_key, sa_salt)

	grpc_client.delsa(sa_vni, sa_spi, "egress", sa_src, sa_dst)
	grpc_client.expect_error(462).delsa(sa_vni, sa_spi, "egress", sa_src, sa_dst)

	# the local side has to be this instance's own underlay prefix, or the association could
	# never match a packet
	grpc_client.expect_error(465).addsa(sa_vni, sa_spi, "egress", sa_dst, sa_src, sa_key, sa_salt)
	grpc_client.expect_error(465).addsa(sa_vni, sa_spi, "ingress", sa_src, sa_dst, sa_key, sa_salt)

	# an outbound association has nothing to replay-check, so a window there would be a number
	# that protects nothing rather than a harmless one
	grpc_client.expect_error(467).addsa(sa_vni, sa_spi, "egress", sa_src, sa_dst, sa_key, sa_salt,
										replay_window=64)

	# and the window dpservice is willing to allocate a bitmap for has an upper bound
	grpc_client.expect_error(467).addsa(sa_vni, sa_spi, "ingress", sa_dst, sa_src, sa_key, sa_salt,
										replay_window=8192)

	# key material length is defined by the algorithm
	grpc_client.expect_failure().addsa(sa_vni, sa_spi, "egress", sa_src, sa_dst, "0011", sa_salt)
	grpc_client.expect_failure().addsa(sa_vni, sa_spi, "egress", sa_src, sa_dst, sa_key, "00")
	grpc_client.expect_failure().addsa(sa_vni, sa_spi, "sideways", sa_src, sa_dst, sa_key, sa_salt)
	# the direction is part of what names an association, so it has to be valid on a lookup too
	grpc_client.expect_failure().getsa(sa_vni, sa_spi, "sideways", sa_src, sa_dst)
	grpc_client.expect_failure().delsa(sa_vni, sa_spi, "sideways", sa_src, sa_dst)

	# ...which is the whole point of naming one: a 128-bit key is the wrong length for the 256-bit
	# cipher and the other way round, and neither is silently padded or truncated
	grpc_client.expect_failure().addsa(sa_vni, sa_spi, "egress", sa_src, sa_dst, sa_key, sa_salt,
									   algorithm="aes-256-gcm")
	grpc_client.expect_failure().addsa(sa_vni, sa_spi, "egress", sa_src, sa_dst, sa_key_256, sa_salt,
									   algorithm="aes-128-gcm")

	grpc_client.expect_failure().addsa(sa_vni, sa_spi, "egress", sa_src, sa_dst, sa_key, sa_salt,
									   algorithm="chacha20-poly1305")


# Replacing an association is a create's worth of parameters applied to a name that already
# exists, so it rejects everything a create rejects - and two things a create cannot.
def test_ipsec_sa_update_errors(prepare_ipv4, grpc_client):
	# there has to be something to replace
	grpc_client.expect_error(462).updatesa(sa_vni, sa_spi, "egress", sa_src, sa_dst,
										   sa_spi + 1, sa_key_alt, sa_salt)

	grpc_client.addsa(sa_vni, sa_spi, "egress", sa_src, sa_dst, sa_key, sa_salt)
	grpc_client.addsa(sa_vni, sa_spi, "ingress", sa_dst, sa_src, sa_key, sa_salt,
					  replay_window=sa_replay_window)

	# an ingress association is filed under the SPI its frames carry, so it cannot be renumbered
	# in place - and rotating its key in place would drop what is still in flight under the old
	# one, which is why the inbound path adds a second association instead
	grpc_client.expect_error(468).updatesa(sa_vni, sa_spi, "ingress", sa_dst, sa_src,
										   sa_spi + 1, sa_key_alt, sa_salt)
	assert grpc_client.getsa(sa_vni, sa_spi, "ingress", sa_dst, sa_src)['key'] == sa_key, 		"A refused replacement disturbed the ingress association"

	# naming the association by a wire SPI it does not carry finds nothing, even though the entry
	# it would replace is filed under the VNI and is right there
	grpc_client.expect_error(462).updatesa(sa_vni, sa_spi + 1, "egress", sa_src, sa_dst,
										   sa_spi + 2, sa_key_alt, sa_salt)

	# the replacement is validated as a fresh association, not as a delta on the old one
	grpc_client.expect_error(467).updatesa(sa_vni, sa_spi, "egress", sa_src, sa_dst,
										   sa_spi + 1, sa_key_alt, sa_salt, replay_window=64)
	grpc_client.expect_error(465).updatesa(sa_vni, sa_spi, "egress", sa_dst, sa_src,
										   sa_spi + 1, sa_key_alt, sa_salt)
	grpc_client.expect_failure().updatesa(sa_vni, sa_spi, "egress", sa_src, sa_dst,
										  sa_spi + 1, sa_key_alt, sa_salt,
										  algorithm="aes-256-gcm")

	# none of which replaced anything
	sa = grpc_client.getsa(sa_vni, sa_spi, "egress", sa_src, sa_dst)
	assert sa['spi'] == sa_spi and sa['key'] == sa_key, 		"A refused replacement left the association changed"

	grpc_client.delsa(sa_vni, sa_spi, "egress", sa_src, sa_dst)
	grpc_client.delsa(sa_vni, sa_spi, "ingress", sa_dst, sa_src)


# What a replacement is: the same name, everything else as asked for. Nothing is carried over from
# the association being replaced, so an omitted field means its default rather than what was there
# before - which is why every one of them is asserted here.
def test_ipsec_sa_update_replaces_everything(prepare_ipv4, grpc_client):
	grpc_client.addsa(sa_vni, sa_spi, "egress", sa_src, sa_dst, sa_key, sa_salt)

	grpc_client.updatesa(sa_vni, sa_spi, "egress", sa_src, sa_dst,
						 sa_spi + 1, sa_key_256, sa_salt, algorithm="aes-256-gcm", esn=True)

	sa = grpc_client.getsa(sa_vni, sa_spi + 1, "egress", sa_src, sa_dst)
	assert sa['spi'] == sa_spi + 1, 		"Replaced association did not take the new wire SPI"
	assert sa['key'] == sa_key_256 and sa['algorithm'] == "aes_256_gcm", 		"Replaced association did not take the new key material"
	assert sa['esn'] is True, 		"Replaced association did not take the options it was given"
	# and it is still one entry, filed where it always was
	assert sa['vni'] == sa_vni and sa['src_underlay'] == sa_src_prefix and sa['dst_underlay'] == sa_dst_prefix, 		"Replacing an association moved it"
	grpc_client.expect_error(462).getsa(sa_vni, sa_spi, "egress", sa_src, sa_dst)

	# an omitted option is its default, not what the association held a moment ago
	grpc_client.updatesa(sa_vni, sa_spi + 1, "egress", sa_src, sa_dst, sa_spi, sa_key, sa_salt)
	sa = grpc_client.getsa(sa_vni, sa_spi, "egress", sa_src, sa_dst)
	assert sa['esn'] is False and sa['algorithm'] == "aes_128_gcm", 		"Replacing an association carried over what it was not asked to keep"

	grpc_client.delsa(sa_vni, sa_spi, "egress", sa_src, sa_dst)


# The two per-association options that change what the cipher does rather than merely which
# addresses it covers. Both are reported back, because a control plane that cannot read them back
# cannot tell an association it configured from one it merely asked for - and for ESN in
# particular a silent disagreement between the two ends fails every frame.
def test_ipsec_sa_algorithm_and_esn(prepare_ipv4, grpc_client):
	grpc_client.addsa(sa_vni, sa_spi, "ingress", sa_dst, sa_src, sa_key_256, sa_salt,
					  algorithm="aes-256-gcm", replay_window=sa_replay_window, esn=True)

	sa = grpc_client.getsa(sa_vni, sa_spi, "ingress", sa_dst, sa_src)
	assert sa['algorithm'] == "aes_256_gcm", \
		"Security Association came back with the wrong algorithm"
	# 64 hex digits, i.e. nothing was cut down to the 128-bit key every other association here uses
	assert sa['key'] == sa_key_256, \
		"256-bit key did not survive the round trip"
	assert sa['esn'] is True, \
		"Security Association created with extended sequence numbers did not report them"
	# the two are independent, and an association can have one without the other
	assert sa['replay_window'] == sa_replay_window, \
		"Extended sequence numbers displaced the anti-replay window"

	grpc_client.delsa(sa_vni, sa_spi, "ingress", sa_dst, sa_src)

	# and the default is off, which is what an association created without the field asks for
	grpc_client.addsa(sa_vni, sa_spi, "egress", sa_src, sa_dst, sa_key, sa_salt)
	assert grpc_client.getsa(sa_vni, sa_spi, "egress", sa_src, sa_dst)['esn'] is False, \
		"Security Association created without --esn came back carrying it"
	grpc_client.delsa(sa_vni, sa_spi, "egress", sa_src, sa_dst)


def test_ipsec_encryption_reported_by_interface(prepare_ipv4, grpc_client):
	# dp_service.py creates every interface with encryption on in this suite, and both ways of
	# asking have to agree - the field on the interface and the dedicated call
	assert grpc_client.getencryption(VM1.name) is True, \
		"Interface encryption is not reported as enabled"
	assert grpc_client.getinterface(VM1.name)['encrypt'] is True, \
		"Interface does not report encryption on its own spec"

	# listinterfaces() reports specs only, the id lives in the metadata it strips
	assert all(iface['encrypt'] is True for iface in grpc_client.listinterfaces()), \
		"ListInterfaces does not report encryption"


def test_ipsec_encryption_toggle(prepare_ipv4, grpc_client):
	# VM3 is on vni2 and has no association, so toggling it changes nothing any other test
	# depends on. It is put back at the end, because the dataplane tests need it encrypting.
	assert grpc_client.getencryption(VM3.name) is True, \
		"VM3 did not start out encrypting"

	# enabling what is already enabled is not silently accepted, matching CaptureStart
	grpc_client.expect_error(210).enableencryption(VM3.name)

	grpc_client.disableencryption(VM3.name)
	assert grpc_client.getencryption(VM3.name) is False, \
		"Encryption is still reported as enabled after being disabled"
	assert grpc_client.getinterface(VM3.name)['encrypt'] is False, \
		"Interface still reports encryption after it was disabled"

	# and disabling what is already disabled likewise, matching CaptureStop
	grpc_client.expect_error(211).disableencryption(VM3.name)

	grpc_client.enableencryption(VM3.name)
	assert grpc_client.getencryption(VM3.name) is True, \
		"Encryption is not reported as enabled after being re-enabled"


def test_ipsec_encryption_unknown_interface(prepare_ipv4, grpc_client):
	grpc_client.expect_error(201).enableencryption("this-does-not-exist")
	grpc_client.expect_error(201).disableencryption("this-does-not-exist")
	grpc_client.expect_error(201).getencryption("this-does-not-exist")
