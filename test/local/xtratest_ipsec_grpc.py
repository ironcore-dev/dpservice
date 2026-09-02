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
sa_spi = vni2
sa_src = local_ul_ipv6
sa_dst = "fc00:3::1"
sa_key = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
sa_key_256 = "0f1e2d3c4b5a69788796a5b4c3d2e1f0c3d2e1f00f1e2d3c4b5a697887960a5b"
sa_salt = "0a1b2c3d"
sa_replay_window = 64

# Only the first 64 bits are matched, so this is what dpservice stores and reports back
sa_src_prefix = "fc00:1::"
sa_dst_prefix = "fc00:3::"


def test_ipsec_sa_lifecycle(prepare_ipv4, grpc_client):
	grpc_client.addsa(sa_spi, "egress", sa_src, sa_dst, sa_key, sa_salt)

	sa = grpc_client.getsa(sa_spi, sa_src, sa_dst)
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

	grpc_client.delsa(sa_spi, sa_src, sa_dst)

	grpc_client.expect_error(462).getsa(sa_spi, sa_src, sa_dst)

# The address pair is a part of the key, so the very same SPI and key is a different
# association in the other direction
def test_ipsec_sa_mirrored_directions(prepare_ipv4, grpc_client):
	grpc_client.addsa(sa_spi, "egress", sa_src, sa_dst, sa_key, sa_salt)
	grpc_client.addsa(sa_spi, "ingress", sa_dst, sa_src, sa_key, sa_salt, replay_window=sa_replay_window)

	assert grpc_client.getsa(sa_spi, sa_src, sa_dst)['direction'] == "egress", \
		"Egress association not found under its own selectors"
	assert grpc_client.getsa(sa_spi, sa_dst, sa_src)['direction'] == "ingress", \
		"Ingress association not found under its own selectors"
	# the window is a property of the one direction that has one, so it is asserted here rather
	# than in the lifecycle test above, whose association is an egress one
	assert grpc_client.getsa(sa_spi, sa_dst, sa_src)['replay_window'] == sa_replay_window, \
		"Ingress association came back with the wrong replay window"
	assert grpc_client.getsa(sa_spi, sa_src, sa_dst)['replay_window'] == 0, \
		"Egress association came back carrying a replay window"

	grpc_client.delsa(sa_spi, sa_src, sa_dst)
	grpc_client.delsa(sa_spi, sa_dst, sa_src)

def test_ipsec_sa_errors(prepare_ipv4, grpc_client):
	grpc_client.addsa(sa_spi, "egress", sa_src, sa_dst, sa_key, sa_salt)

	# a second create would otherwise silently replace the association and leak the old one
	grpc_client.expect_error(461).addsa(sa_spi, "egress", sa_src, sa_dst, sa_key, sa_salt)

	grpc_client.delsa(sa_spi, sa_src, sa_dst)
	grpc_client.expect_error(462).delsa(sa_spi, sa_src, sa_dst)

	# the local side has to be this instance's own underlay prefix, or the association could
	# never match a packet
	grpc_client.expect_error(465).addsa(sa_spi, "egress", sa_dst, sa_src, sa_key, sa_salt)
	grpc_client.expect_error(465).addsa(sa_spi, "ingress", sa_src, sa_dst, sa_key, sa_salt)

	# an outbound association has nothing to replay-check, so a window there would be a number
	# that protects nothing rather than a harmless one
	grpc_client.expect_error(467).addsa(sa_spi, "egress", sa_src, sa_dst, sa_key, sa_salt,
										replay_window=64)

	# and the window dpservice is willing to allocate a bitmap for has an upper bound
	grpc_client.expect_error(467).addsa(sa_spi, "ingress", sa_dst, sa_src, sa_key, sa_salt,
										replay_window=8192)

	# key material length is defined by the algorithm
	grpc_client.expect_failure().addsa(sa_spi, "egress", sa_src, sa_dst, "0011", sa_salt)
	grpc_client.expect_failure().addsa(sa_spi, "egress", sa_src, sa_dst, sa_key, "00")
	grpc_client.expect_failure().addsa(sa_spi, "sideways", sa_src, sa_dst, sa_key, sa_salt)

	# ...which is the whole point of naming one: a 128-bit key is the wrong length for the 256-bit
	# cipher and the other way round, and neither is silently padded or truncated
	grpc_client.expect_failure().addsa(sa_spi, "egress", sa_src, sa_dst, sa_key, sa_salt,
									   algorithm="aes-256-gcm")
	grpc_client.expect_failure().addsa(sa_spi, "egress", sa_src, sa_dst, sa_key_256, sa_salt,
									   algorithm="aes-128-gcm")

	grpc_client.expect_failure().addsa(sa_spi, "egress", sa_src, sa_dst, sa_key, sa_salt,
									   algorithm="chacha20-poly1305")


# The two per-association options that change what the cipher does rather than merely which
# addresses it covers. Both are reported back, because a control plane that cannot read them back
# cannot tell an association it configured from one it merely asked for - and for ESN in
# particular a silent disagreement between the two ends fails every frame.
def test_ipsec_sa_algorithm_and_esn(prepare_ipv4, grpc_client):
	grpc_client.addsa(sa_spi, "ingress", sa_dst, sa_src, sa_key_256, sa_salt,
					  algorithm="aes-256-gcm", replay_window=sa_replay_window, esn=True)

	sa = grpc_client.getsa(sa_spi, sa_dst, sa_src)
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

	grpc_client.delsa(sa_spi, sa_dst, sa_src)

	# and the default is off, which is what an association created without the field asks for
	grpc_client.addsa(sa_spi, "egress", sa_src, sa_dst, sa_key, sa_salt)
	assert grpc_client.getsa(sa_spi, sa_src, sa_dst)['esn'] is False, \
		"Security Association created without --esn came back carrying it"
	grpc_client.delsa(sa_spi, sa_src, sa_dst)
