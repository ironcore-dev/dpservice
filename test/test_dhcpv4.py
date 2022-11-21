from helpers import *


def runtest(interface, macaddr, ipaddr):

	scapy.config.conf.checkIPaddr = False
	answer = dhcp_request(iface=interface, timeout=5)
	resp = str(answer[DHCP].options[0][1])
	assert str(resp) == str(2)

	dst_mac = answer[Ether].src
	dst_ip = answer[IP].src
	pkt = (Ether(dst=dst_mac) /
		   IP(src=ipaddr, dst=dst_ip) /
		   UDP(sport=68, dport=67) /
		   BOOTP(chaddr=macaddr) /
		   DHCP(options=[("message-type", "request"), "end"]))
	answer = srp1(pkt, iface=interface)
	assert str(answer[BOOTP].yiaddr) == ipaddr


def test_dhcpv4_vf0(add_machine):
	runtest(vf0_tap, vf0_mac, vf0_ip)

def test_dhcpv4_vf1(add_machine):
	runtest(vf1_tap, vf1_mac, vf1_ip)
