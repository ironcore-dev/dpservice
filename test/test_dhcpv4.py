from helpers import *


def runtest(interface, macaddr, ipaddr):

	scapy.config.conf.checkIPaddr = False
	answer = dhcp_request(iface=interface, timeout=5)
	msg_type = answer[DHCP].options[0][1]
	assert msg_type == 2, \
		f"DHCP message is not DHCPOFFER (message type: {msg_type})"

	pkt = (Ether(dst=answer[Ether].src) /
		   IP(src=ipaddr, dst=answer[IP].src) /
		   UDP(sport=68, dport=67) /
		   BOOTP(chaddr=macaddr) /
		   DHCP(options=[("message-type", "request"), "end"]))
	answer = srp1(pkt, iface=interface)
	assigned_ip = answer[BOOTP].yiaddr
	assert assigned_ip == ipaddr, \
		f"Wrong address assigned ({assigned_ip})"

def test_dhcpv4_vf0(add_machine):
	runtest(vf0_tap, vf0_mac, vf0_ip)

def test_dhcpv4_vf1(add_machine):
	runtest(vf1_tap, vf1_mac, vf1_ip)
