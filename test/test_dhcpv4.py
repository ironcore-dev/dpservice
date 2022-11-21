from helpers import *


def test_dhcpv4_vf0(prepare_ifaces):
	request_ip(vf0_tap, vf0_mac, vf0_ip)

def test_dhcpv4_vf1(prepare_ifaces):
	request_ip(vf1_tap, vf1_mac, vf1_ip)
