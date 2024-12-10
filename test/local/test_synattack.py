# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import pytest

from config import *
from helpers import *
from tcp_tester import TCPTesterPublic


def test_cntrack(request, prepare_ipv4, grpc_client):
	# Only allow one port for this test, so the next call would normally fail (NAT runs out of free ports)
	nat_ul_ipv6 = grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_min_port+1)

	tester = TCPTesterPublic(VM1, 12344, nat_ul_ipv6, PF0, public_ip, 443)
	# tester.communicate()
	tester.synattack()

	grpc_client.delnat(VM1.name)
