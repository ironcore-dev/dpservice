# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

from helpers import *

def test_nd(prepare_ifaces):
	answer = neighsol(gateway_ipv6, VM1.ipv6, iface=VM1.tap, timeout=sniff_timeout)
	validate_checksums(answer)
	lladdr = answer[ICMPv6NDOptDstLLAddr].lladdr
	assert lladdr == VM1.mac, \
		f"Wrong neighbor link-level address ({lladdr})"
