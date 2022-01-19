from scapy.all import *
from scapy.layers.l2 import ARP
from scapy.layers.inet import Ether
from scapy.layers.dhcp import *
from scapy.config import conf

import pytest, shlex, subprocess, time
from config import *

@pytest.fixture(scope="module")
def add_machine(build_path):
	add_machine_cmd = build_path+"/test/dp_grpc_client --addmachine 1 --vni 100 --ipv4 172.32.10.5 --ipv6 2001::10"
	subprocess.run(shlex.split("ip link set dev "+vf0_tap+" up"))
	subprocess.run(shlex.split(add_machine_cmd))
	time.sleep(1)


def test_l2_arp(add_machine):
	try:
		arp_packet = Ether(dst=bcast_mac)/ARP(pdst=gw_ip4, hwdst=vf0_mac, psrc=null_ip)
		answer, unanswered = srp(arp_packet, iface=vf0_tap, type=ETH_P_ARP, timeout=2)

		for sent, received in answer:
			assert (str(received[ARP].hwsrc) == vf0_mac)
		time.sleep(1)
	except Exception as e:
		prepare_env.terminate()


def test_dhcpv4(capsys,add_machine):
	conf.checkIPaddr = False
	answer = dhcp_request(iface=vf0_tap, timeout=5)
	resp = str(answer[DHCP].options[0][1])
	print(str(resp))
	pytest.assume(str(resp) == str(2))
	dst_mac = answer[Ether].src
	dst_ip = answer[IP].src
	answer = srp1(Ether(dst=dst_mac) / IP(src=vf0_ip, dst=dst_ip) / UDP(sport=68, dport=67) /
                BOOTP(chaddr=vf0_mac) / DHCP(options=[("message-type", "request"), "end"]), iface=vf0_tap)
	print(str(answer[BOOTP].yiaddr))
	assert (str(answer[BOOTP].yiaddr) == vf0_ip)
	
	

