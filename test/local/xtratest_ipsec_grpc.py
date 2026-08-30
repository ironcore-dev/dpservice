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
sa_salt = "0a1b2c3d"

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
	grpc_client.addsa(sa_spi, "ingress", sa_dst, sa_src, sa_key, sa_salt)

	assert grpc_client.getsa(sa_spi, sa_src, sa_dst)['direction'] == "egress", \
		"Egress association not found under its own selectors"
	assert grpc_client.getsa(sa_spi, sa_dst, sa_src)['direction'] == "ingress", \
		"Ingress association not found under its own selectors"

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

	# key material length is defined by the algorithm
	grpc_client.expect_failure().addsa(sa_spi, "egress", sa_src, sa_dst, "0011", sa_salt)
	grpc_client.expect_failure().addsa(sa_spi, "egress", sa_src, sa_dst, sa_key, "00")
	grpc_client.expect_failure().addsa(sa_spi, "sideways", sa_src, sa_dst, sa_key, sa_salt)
