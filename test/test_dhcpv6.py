from helpers import *


def test_dhcpv6(prepare_ifaces):

	DUID = DUID_LL(lladdr=VM1.mac)
	IAID = 0x18702501

	eth = Ether(dst=ipv6_multicast_mac)
	ip6 = IPv6(dst=gateway_ipv6)
	udp = UDP()

	rc_op = DHCP6OptRapidCommit()
	opreq = DHCP6OptOptReq()
	et_op = DHCP6OptElapsedTime()
	cid_op = DHCP6OptClientId(duid=DUID)
	iana_op = DHCP6OptIA_NA(iaid=IAID, T1=0, T2=0)

	sol = DHCP6_Solicit(trid=random.randint(0, 16777215))
	pkt = eth / ip6 / udp / sol / iana_op / rc_op / et_op / cid_op / opreq
	answer = srp1(pkt, iface=VM1.tap, type=ETH_P_IPV6, timeout=sniff_timeout)
	validate_checksums(answer)
	duid = answer[DHCP6OptClientId].duid
	assert duid == DUID, \
		f"Bad duid in DHCPv6 Solicit ({duid})"
	assert answer[DHCP6OptIA_NA].iaid == IAID, \
		f"Bad IA id in DHCPv6 Solicit"

	req = DHCP6_Request()
	iana_op = DHCP6OptIA_NA(iaid=IAID, T1=0, T2=0, ianaopts=[answer[DHCP6OptIAAddress]])
	pkt = eth / ip6 / udp / req / iana_op / rc_op / et_op / cid_op / opreq
	answer = srp1(pkt, iface=VM1.tap, type=ETH_P_IPV6, timeout=sniff_timeout)
	validate_checksums(answer)
	duid == answer[DHCP6OptClientId].duid
	assert duid == DUID, \
		f"Bad duid in DHCPv6 Request ({duid})"
	assert answer[DHCP6OptIA_NA].iaid == IAID, \
		f"Bad IA id in DHCPv6 Request"
	assigned_ipv6 = answer[DHCP6OptIAAddress].addr
	assert assigned_ipv6 == VM1.ipv6, \
		f"Wrong address assigned ({assigned_ipv6})"

	req = DHCP6_Confirm()
	pkt = eth / ip6 / udp / req / et_op
	answer = srp1(pkt, iface=VM1.tap, type=ETH_P_IPV6, timeout=sniff_timeout)
	validate_checksums(answer)
	assert DHCP6_Reply in answer, \
		f"No proper reply to DHCPv6 confirm packet"
