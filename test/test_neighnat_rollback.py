import pytest
import threading

from helpers import *


def test_nat_capacity(prepare_ipv4, grpc_client):
	grpc_client.addneighnat("1.2.3.4", vni1, 2100, 2200, "fe80::1:1")
	grpc_client.addneighnat("1.2.3.5", vni1, 2100, 2200, "fe80::1:1")
	# this will not fit and will fail on capacity
	grpc_client.expect_error(322).addneighnat("1.2.3.6", vni1, 2200, 2300, "fe80::1:1")
	# but the NAT entry is not cleaned-up
	grpc_client.delneighnat("1.2.3.5", vni1, 2100, 2200)
	grpc_client.delneighnat("1.2.3.4", vni1, 2100, 2200)
	grpc_client.addnat(VM1.name, "1.2.3.6", 2100, 2200)
	grpc_client.delnat(VM1.name) # THIS will not remove the DNAT entry because there there still is the non-rolled back one
	grpc_client.addvip(VM1.name, "1.2.3.6") # Which will cause this to fail
