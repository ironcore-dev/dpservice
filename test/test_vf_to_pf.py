import threading
import time

from config import *
from helpers import *
from responders import *


def send_icmp_pkt_from_vm1():

	pkt_list = sniff(count=1, lfilter=is_icmp_pkt, iface=pf0_tap, timeout=10)
	assert len(pkt_list) == 1, 'Cannot receive network-natted tcp pkt on pf'

	pkt = pkt_list[0]

	if Ether in pkt:
		pktether = pkt[Ether]
	if IPv6 in pkt:
		pktipv6 = pkt[IPv6]
	if IP in pkt:
		pktip = pkt[IP]
	if ICMP in pkt:
		pkticmp = pkt[ICMP]

	if pktip.src == nat_vip:
		reply_pkt = (Ether(dst=pktether.src, src=pktether.dst, type=0x86DD) /
					 IPv6(dst=ul_actual_src, src=pktipv6.dst, nh=4) /
					 IP(dst=pktip.src, src=pktip.dst) /
					 ICMP(type=0, id=pkticmp.id))
		sendp(reply_pkt, iface=pf0_tap)

def test_vf_to_pf_network_nat_icmp(add_machine, request_ip_vf0, grpc_client):

	grpc_client.assert_output(f"--addnat {vm1_name} --ipv4 {nat_vip} --min_port {nat_local_min_port} --max_port {nat_local_max_port}",
		"Received underlay route")

	threading.Thread(target=send_icmp_pkt_from_vm1).start()

	time.sleep(1)

	icmp_pkt = (Ether(dst=pf0_mac, src=vf0_mac, type=0x0800) /
			    IP(dst=public_ip, src=vf0_ip) /
			    ICMP(type=8, id=0x0040))
	sendp(icmp_pkt, iface = vf0_tap)

	pkt_list = sniff(count=1, lfilter=is_icmp_pkt, iface=vf0_tap, timeout=3)
	assert len(pkt_list) == 1

	pkt = pkt_list[0]

	if Ether in pkt:
		pktether = pkt[Ether]
	if IPv6 in pkt:
		pktipv6 = pkt[IPv6]
	if IP in pkt:
		pktip = pkt[IP]
	if ICMP in pkt:
		pkticmp = pkt[ICMP]

	assert pktip.dst == vf0_ip, 'Received wrong icmp packet with ip:'+pktip.dst

	grpc_client.assert_output(f"--delnat {vm1_name}",
		"NAT deleted")


def send_tcp_pkt_from_vm1():

	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=pf0_tap, timeout=10)
	assert len(pkt_list) == 1, 'Cannot receive network-natted tcp pkt on pf'

	pkt = pkt_list[0]

	if Ether in pkt:
		pktether = pkt[Ether]
	if IPv6 in pkt:
		pktipv6 = pkt[IPv6]
	if IP in pkt:
		pktip = pkt[IP]
	if TCP in pkt:
		pkttcp = pkt[TCP]

	if pktip.src == nat_vip and pkttcp.sport == nat_local_min_port:
		reply_pkt = (Ether(dst=pktether.src, src=pktether.dst, type=0x86DD) /
					 IPv6(dst=ul_actual_src, src=pktipv6.dst, nh=4) /
					 IP(dst=pktip.src, src=pktip.dst) /
					 TCP(sport=pkttcp.dport, dport=pkttcp.sport))
		time.sleep(1)
		sendp(reply_pkt, iface=pf0_tap)

def test_vf_to_pf_network_nat_tcp(add_machine, request_ip_vf0, grpc_client):

	# TODO(plague) I suspect that there is an occasional problem here
	# as this test is called immediately after the previous one, that established and then teared down the same route
	# there will be a race condition and the service needs more time this time around
	grpc_client.assert_output(f"--addnat {vm1_name} --ipv4 {nat_vip} --min_port {nat_local_min_port} --max_port {nat_local_max_port}",
		"Received underlay route")

	threading.Thread(target=send_tcp_pkt_from_vm1).start()

	time.sleep(2)

	tcp_pkt = (Ether(dst=pf0_mac, src=vf0_mac, type=0x0800) /
			   IP(dst=public_ip, src=vf0_ip) /
			   TCP(sport=1240))
	sendp(tcp_pkt, iface=vf0_tap)

	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=vf0_tap, timeout=10)
	assert len(pkt_list) == 1, 'Cannot receive network-natted tcp pkt on pf'

	pkt = pkt_list[0]

	if Ether in pkt:
		pktether = pkt[Ether]
	if IPv6 in pkt:
		pktipv6 = pkt[IPv6]
	if IP in pkt:
		pktip = pkt[IP]
	if TCP in pkt:
		pkttcp = pkt[TCP]

	assert pktip.dst == vf0_ip and pkttcp.dport == 1240, 'Received wrong packet with ip:'+pktip.dst+" dport:"+str(pkttcp.dport)

	grpc_client.assert_output(f"--delnat {vm1_name}",
		"NAT deleted")


def test_vf_to_pf_vip_snat(add_machine, request_ip_vf0, request_ip_vf1, grpc_client):

	threading.Thread(target=encaped_tcp_in_ipv6_vip_responder, args=(pf0_tap,)).start()
	# TODO why is this here? This one does not ever fire (even with redundancy)
	# I thought that was the reason, the comment below seems to indicate that too
	threading.Thread(target=encaped_tcp_in_ipv6_vip_responder, args=(pf1_tap,)).start()

	grpc_client.assert_output(f"--addvip {vm2_name} --ipv4 {virtual_ip}",
		f"Received underlay route : {ul_actual_src}")

	time.sleep(1)

	# vm2 (vf1) -> PF0/PF1 (internet traffic), vm2 has VIP, check on PFs side, whether VIP is source (SNAT)
	tcp_pkt = (Ether(dst=pf0_mac, src=vf1_mac, type=0x0800) /
			   IP(dst=public_ip, src=vf1_ip) /
			   TCP(sport=1240))
	sendp(tcp_pkt, iface=vf1_tap)

	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=vf1_tap, timeout=5)
	assert len(pkt_list) == 1, 'Cannot receive tcp reply via VIP (SNAT)!'

	grpc_client.assert_output(f"--delvip {vm2_name}",
		"VIP deleted")
