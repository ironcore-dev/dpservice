from helpers import *


def test_dhcpv6(add_machine):

	eth = Ether(dst=mc_mac)
	ip6 = IPv6(dst=gw_ip6)
	udp = UDP(sport=546, dport=547)
	sol = DHCP6_Solicit()
	req = DHCP6_Request()

	sol.trid = random.randint(0, 16777215)
	rc_op = DHCP6OptRapidCommit(optlen=0)
	opreq = DHCP6OptOptReq()
	et_op= DHCP6OptElapsedTime()
	cid_op = DHCP6OptClientId()
	iana_op = DHCP6OptIA_NA(iaid=0x18702501)

	iana_op.optlen = 12
	iana_op.T1 = 0
	iana_op.T2 = 0
	cid_op.optlen = 28
	cid_op.duid = "00020000ab11b7d4e0eed266171d"
	opreq.optlen = 4

	pkt = eth/ip6/udp/sol/iana_op/rc_op/et_op/cid_op/opreq
	answer = srp1(pkt, iface=vf0_tap, type=ETH_P_IPV6, timeout=2)
	assert str(cid_op.duid) == str(answer[DHCP6OptClientId].duid)

	iana_op = answer[DHCP6OptIAAddress]
	pkt = eth / ip6 / udp / req / iana_op / rc_op / et_op / cid_op / opreq
	answer = srp1(pkt, iface=vf0_tap, type=ETH_P_IPV6, timeout=2)
	assert str(cid_op.duid) == str(answer[DHCP6OptClientId].duid)
	assert str(answer[DHCP6OptIAAddress].addr) == vf0_ipv6
