# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

from helpers import *
from scapy.layers.dhcp6 import *

PXE_MODE = 0
IPXE_MODE = 1

class SubOptionField(Packet):
	name = "SubOptionField"
	fields_desc = [
		ShortField("subopt_len", None),  # 2 bytes for suboption length
		StrLenField("subopt_data", "", length_from=lambda pkt: pkt.subopt_len)
	]
	def extract_padding(self, p):
		return "", p

# Via library provided DHCP6OptUserClass doesnt consider suboption length, so extend it
class DHCP6OptUserClassWithSubOption(DHCP6OptUserClass):
	fields_desc = [
		ShortEnumField("optcode", 15, dhcp6opts),
		ShortField("optlen", None),
		PacketListField("user_class_data", [], SubOptionField,
						length_from=lambda pkt: pkt.optlen)
	]
	def post_build(self, p, pay):
		if self.optlen is None:
			length = len(p) - 4
			p = p[:2] + struct.pack("!H", length) + p[4:]
		return p + pay

def request_ipv6(vm, pxe_mode):
	DUID = DUID_LL(lladdr=vm.mac)
	IAID = 0x18702501
	pxe_class = None
	expected_url = None
	#Encode the two byte length in the opaque data as per RFC 3315 22.16
	vendor_class_data = b'\x00\x20PXEClient:Arch:00007:UNDI:003016'
	user_class_data = b'iPXE'

	eth = Ether(dst=ipv6_multicast_mac)
	ip6 = IPv6(dst=gateway_ipv6)
	udp = UDP()

	rc_op = DHCP6OptRapidCommit()
	opreq = DHCP6OptOptReq()
	et_op = DHCP6OptElapsedTime()
	cid_op = DHCP6OptClientId(duid=DUID)
	iana_op = DHCP6OptIA_NA(iaid=IAID, T1=0, T2=0)
	if pxe_mode == PXE_MODE:
		pxe_class = DHCP6OptVendorClass(enterprisenum=343, vcdata=vendor_class_data)
	elif pxe_mode == IPXE_MODE:
		suboption_field = SubOptionField(subopt_len=len(user_class_data), subopt_data=user_class_data)
		pxe_class = DHCP6OptUserClassWithSubOption(user_class_data=[suboption_field])
	else:
		assert True, "Unknown pxe mode"

	opt_req = DHCP6OptOptReq(reqopts=[59])

	sol = DHCP6_Solicit(trid=random.randint(0, 16777215))
	pkt = eth / ip6 / udp / sol / iana_op / rc_op / et_op / cid_op / opt_req / pxe_class
	answer = srp1(pkt, iface=vm.tap, type=ETH_P_IPV6, timeout=sniff_timeout)
	validate_checksums(answer)
	duid = answer[DHCP6OptClientId].duid
	assert duid == DUID, \
		f"Bad duid in DHCPv6 Solicit ({duid})"
	assert answer[DHCP6OptIA_NA].iaid == IAID, \
		f"Bad IA id in DHCPv6 Solicit"

	# Extracting the DNS servers from the DHCPv6 reply
	dns_servers = None
	if DHCP6OptDNSServers in answer:
		dns_servers = answer[DHCP6OptDNSServers].dnsservers

	# Check if DNS servers option is in DHCPv6 reply
	assert dns_servers is not None, \
		f"No DNS servers option in DHCPv6 reply"

	# Check if the correct DNS servers are specified in the DHCPv6 reply
	assert dhcpv6_dns1 in dns_servers and dhcpv6_dns2 in dns_servers, \
		f"DHCPv6 reply does not specify the correct DNS servers: {dns_servers} instead of {dhcpv6_dns1} and {dhcpv6_dns2}"

	boot_file_url_option = answer.getlayer(DHCP6OptBootFileUrl)
	assert boot_file_url_option is not None, "Boot File URL option not in DHCPv6 reply"
	boot_file_url = boot_file_url_option.optdata
	if pxe_mode == PXE_MODE:
		expected_url = f"tftp://[{pxe_server}]/{pxe_file_name}"
	else:
		expected_url = f"http://[{pxe_server}]/{ipxe_file_name}"
	assert boot_file_url.decode('utf-8') == expected_url, f"Received Boot File URL is incorrect: {boot_file_url.decode('utf-8')}"

	req = DHCP6_Request()
	iana_op = DHCP6OptIA_NA(iaid=IAID, T1=0, T2=0, ianaopts=[answer[DHCP6OptIAAddress]])
	pkt = eth / ip6 / udp / req / iana_op / rc_op / et_op / cid_op / opreq / pxe_class
	answer = srp1(pkt, iface=vm.tap, type=ETH_P_IPV6, timeout=sniff_timeout)
	validate_checksums(answer)
	duid == answer[DHCP6OptClientId].duid
	assert duid == DUID, \
		f"Bad duid in DHCPv6 Request ({duid})"
	assert answer[DHCP6OptIA_NA].iaid == IAID, \
		f"Bad IA id in DHCPv6 Request"
	assigned_ipv6 = answer[DHCP6OptIAAddress].addr
	assert assigned_ipv6 == vm.ipv6, \
		f"Wrong address assigned ({assigned_ipv6})"

	req = DHCP6_Confirm()
	pkt = eth / ip6 / udp / req / et_op
	answer = srp1(pkt, iface=vm.tap, type=ETH_P_IPV6, timeout=sniff_timeout)
	validate_checksums(answer)
	assert DHCP6_Reply in answer, \
		f"No proper reply to DHCPv6 confirm packet"


def test_dhcpv6_vf0(prepare_ifaces):
	request_ipv6(VM1, PXE_MODE)

def test_dhcpv6_vf1(prepare_ifaces):
	request_ipv6(VM2, IPXE_MODE)