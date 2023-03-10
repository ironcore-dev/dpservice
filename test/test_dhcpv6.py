from helpers import *


def test_dhcpv6(prepare_ifaces):

	DUID = b"00020000ab11b7d4e0eed266171d"

	eth = Ether(dst=ipv6_multicast_mac)
	ip6 = IPv6(dst=gateway_ipv6)
	udp = UDP(sport=546, dport=547)

	rc_op = DHCP6OptRapidCommit(optlen=0)
	opreq = DHCP6OptOptReq(optlen=4)
	et_op = DHCP6OptElapsedTime()
	cid_op = DHCP6OptClientId(optlen=28, duid=DUID)
	iana_op = DHCP6OptIA_NA(optlen=12, iaid=0x18702501, T1=0, T2=0)

	sol = DHCP6_Solicit(trid=random.randint(0, 16777215))
	pkt = eth / ip6 / udp / sol / iana_op / rc_op / et_op / cid_op / opreq
	answer = srp1(pkt, iface=VM1.tap, type=ETH_P_IPV6, timeout=sniff_timeout)
	validate_checksums(answer)
	duid = bytes(answer[DHCP6OptClientId].duid)
	assert duid == DUID, \
		f"Bad duid in DHCPv6 Solicit ({duid})"

	req = DHCP6_Request()
	iana_op = answer[DHCP6OptIAAddress]
	pkt = eth / ip6 / udp / req / iana_op / rc_op / et_op / cid_op / opreq
	answer = srp1(pkt, iface=VM1.tap, type=ETH_P_IPV6, timeout=sniff_timeout)
	validate_checksums(answer)
	duid == bytes(answer[DHCP6OptClientId].duid)
	assert duid == DUID, \
		f"Bad duid in DHCPv6 Request ({duid})"
	assigned_ipv6 = answer[DHCP6OptIAAddress].addr
	assert assigned_ipv6 == VM1.ipv6, \
		f"Wrong address assigned ({assigned_ipv6})"
