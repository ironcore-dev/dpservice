from sys import stdout
from scapy.all import *
from scapy.layers.l2 import ARP
from scapy.layers.inet import Ether, ICMP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.dhcp import *
from scapy.config import conf
from scapy.contrib.geneve import GENEVE

import pytest, shlex, subprocess, time
from config import *

import multiprocessing

def test_l2_arp(add_machine):
	try:
		arp_packet = Ether(dst=bcast_mac)/ARP(pdst=gw_ip4, hwdst=vf0_mac, psrc=null_ip)
		answer, unanswered = srp(arp_packet, iface=vf0_tap, type=ETH_P_ARP, timeout=2)

		for sent, received in answer:
			assert (str(received[ARP].hwsrc) == vf0_mac)
		time.sleep(1)
	except Exception as e:
		prepare_env.terminate()


def test_dhcpv4_vf0(capsys,add_machine):
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

def test_dhcpv4_vf1(capsys,add_machine):
	conf.checkIPaddr = False
	answer = dhcp_request(iface=vf1_tap, timeout=5)
	resp = str(answer[DHCP].options[0][1])
	print(str(resp))
	pytest.assume(str(resp) == str(2))
	dst_mac = answer[Ether].src
	dst_ip = answer[IP].src
	answer = srp1(Ether(dst=dst_mac) / IP(src=vf1_ip, dst=dst_ip) / UDP(sport=68, dport=67) /
				BOOTP(chaddr=vf0_mac) / DHCP(options=[("message-type", "request"), "end"]), iface=vf1_tap)
	print(str(answer[BOOTP].yiaddr))
	assert (str(answer[BOOTP].yiaddr) == vf1_ip)

def is_encaped_icmp_pkt(pkt):
	if IPv6 in pkt:
		pktipv6=pkt[IPv6]
		if pktipv6.dst==ul_actual_dst and pktipv6.nh==4:
			if ICMP in pkt:
				return True
	return False

def is_geneve_encaped_icmp_pkt(pkt):
	if IPv6 in pkt:
		pktipv6=pkt[IPv6]
		if pktipv6.dst==ul_actual_dst and pktipv6.nh==17:
			if ICMP in pkt:
				return True
	return False

def is_icmp_pkt(pkt):
	if ICMP in pkt:
		return True
	return False

def is_tcp_pkt(pkt):
	if TCP in pkt:
		return True
	return False

def is_tcp_vip_src_pkt(pkt):
	if TCP in pkt:
		if pkt[IP].src == virtual_ip:
			return True
	return False

def ipv4_in_ipv6_responder(pf_name):
	pkt_list = sniff(count=1,lfilter=is_encaped_icmp_pkt,iface=pf_name,timeout=10)

	if len(pkt_list)==0:
		return 

	pkt=pkt_list[0]
	pkt.show()
	if Ether in pkt:
		pktether=pkt[Ether]
	if IPv6 in pkt:
		pktipv6 = pkt[IPv6]
	if IP in pkt:
		pktip= pkt[IP]

	reply_pkt = Ether(dst=pktether.src, src=pktether.dst, type=0x86DD)/IPv6(dst=ul_actual_src, src=pktipv6.dst, nh=4)/IP(dst=pktip.src, src=pktip.dst) / ICMP(type=0)
	time.sleep(1)
	sendp(reply_pkt, iface=pf_name)

def encaped_tcp_in_ipv6_vip_responder(pf_name):
	pkt_list = sniff(count=1,lfilter=is_tcp_pkt,iface=pf_name,timeout=10)

	if len(pkt_list)==0:
		return 

	pkt=pkt_list[0]
	pkt.show()
	if Ether in pkt:
		pktether=pkt[Ether]
	if IPv6 in pkt:
		pktipv6 = pkt[IPv6]
	if IP in pkt:
		pktip= pkt[IP]
	if TCP in pkt:
		pkttcp = pkt[TCP]

	reply_pkt = Ether(dst=pktether.src, src=pktether.dst, type=0x86DD)/IPv6(dst=ul_actual_src, src=pktipv6.dst, nh=4)/IP(dst=pktip.src, src=pktip.dst) /TCP(sport=pkttcp.dport, dport=pkttcp.sport)
	time.sleep(1)
	sendp(reply_pkt, iface=pf_name)

def geneve_in_ipv6_responder(pf_name):
	pkt_list = sniff(count=1,lfilter=is_geneve_encaped_icmp_pkt, iface=pf_name,timeout=8)
	pkt=pkt_list[0]
	pkt.show()

	if Ether in pkt:
		pktether=pkt[Ether]
	if IPv6 in pkt:
		pktipv6 = pkt[IPv6]
	if IP in pkt:
		pktip = pkt[IP]

	reply_pkt = Ether(dst=pktether.src, src=pktether.dst, type=0x86DD)/IPv6(dst=ul_actual_src, src=pktipv6.dst, nh=17) / UDP(sport=6081, dport=6081) \
				/ GENEVE(vni=0x640000, proto=0x0800) / IP(dst=pktip.src, src=pktip.dst) / ICMP(type=0)
	time.sleep(1)
	sendp(reply_pkt, iface=pf_name)

@pytest.mark.skipif(port_redundancy == True, reason = "port reduncy test already includes this one")
def test_IPv4inIPv6(capsys, add_machine, tun_opt):
	d = None
	if tun_opt == tun_type_geneve:
		d = multiprocessing.Process(name="sniffer",target = geneve_in_ipv6_responder,args=(pf0_tap,))
	else:
		d = multiprocessing.Process(name="sniffer",target = ipv4_in_ipv6_responder, args=(pf0_tap,))
	d.daemon=False
	d.start()

	time.sleep(1)
	icmp_echo_pkt = Ether(dst=pf0_mac,src=vf0_mac,type=0x0800)/IP(dst="192.168.129.5",src="172.32.10.5")/ICMP(type=8)
	sendp(icmp_echo_pkt,iface=vf0_tap)

	pkt_list = sniff(count=1,lfilter=is_icmp_pkt,iface=vf0_tap,timeout=5)
	if len(pkt_list)==0:
		raise AssertionError('Cannot receive icmp reply!')

@pytest.mark.skipif(port_redundancy == False, reason = "no need to test port redundancy if it is disabled")
def test_link_redundancy_handling(capsys, add_machine,tun_opt):
	d = None
	d2 = None
	if tun_opt == tun_type_geneve:
		d = multiprocessing.Process(name="sniffer",target = geneve_in_ipv6_responder, args=(pf0_tap,))
		d2 = multiprocessing.Process(name="sniffer",target = geneve_in_ipv6_responder, args=(pf1_tap,))
	else:
		d = multiprocessing.Process(name="sniffer",target = ipv4_in_ipv6_responder, args=(pf0_tap,))
		d2 = multiprocessing.Process(name="sniffer",target = ipv4_in_ipv6_responder,args=(pf1_tap,))
	d.daemon=False
	d.start()

	d2.daemon=False
	d2.start()

	time.sleep(0.5)

	icmp_echo_pkt = Ether(dst=pf0_mac,src=vf0_mac,type=0x0800)/IP(dst="192.168.129.5",src="172.32.10.5")/ICMP(type=8)
	sendp(icmp_echo_pkt,iface=vf0_tap)
	pkt_list = sniff(count=1,lfilter=is_icmp_pkt,iface=vf0_tap,timeout=2)

	time.sleep(0.5)

	icmp_echo_pkt = Ether(dst=pf0_mac,src=vf0_mac,type=0x0800)/IP(dst="192.168.129.6",src="172.32.10.5")/ICMP(type=8)
	sendp(icmp_echo_pkt,iface=vf0_tap)
	pkt_list2 = sniff(count=1,lfilter=is_icmp_pkt,iface=vf0_tap,timeout=2)

	subprocess.run(shlex.split("ip link set dev "+pf1_tap+" up"))
	if len(pkt_list)!=1 and len(pkt_list2) !=1:
		raise AssertionError('Cannot receive icmp reply!')


def vf_to_vf_tcp_vf1_responder():
	pkt_list = sniff(count=1,lfilter=is_tcp_pkt,iface=vf1_tap)
	pkt=pkt_list[0]

	if Ether in pkt:
		pktether = pkt[Ether]
	if IP in pkt:
		pktip = pkt[IP]
	if TCP in pkt:
		pkttcp = pkt[TCP]

	reply_pkt = Ether(dst=pktether.src,src=pktether.dst,type=0x0800)/IP(dst=pktip.src,src=pktip.dst)/TCP(sport=pkttcp.dport, dport=pkttcp.sport)
	time.sleep(1)
	sendp(reply_pkt, iface=vf1_tap)


def test_vf_to_vf_tcp(capsys,add_machine):
	d=multiprocessing.Process(name="sniffer",target=vf_to_vf_tcp_vf1_responder)
	d.daemon=False
	d.start()

	time.sleep(1)

	tcp_pkt = Ether(dst=vf1_mac,src=vf0_mac,type=0x0800)/IP(dst=vf1_ip,src=vf0_ip)/TCP()
	sendp(tcp_pkt,iface=vf0_tap)
	
	pkt_list = sniff(count=1,lfilter=is_tcp_pkt,iface=vf0_tap,timeout=2)
	if len(pkt_list)==0:
		raise AssertionError('Cannot receive tcp reply!')

def eval_cmd_output(cmd_str, exp_error, negate=False, maxlines=5):
	cmd = shlex.split(cmd_str)
	process = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)
	count = 0
	first_line = ""
	err_found = False

	while count < maxlines:
		output = process.stdout.readline()
		line = output.strip()
		if count == 0:
			first_line = line
		if exp_error in line:
			err_found = True
		count = count + 1
	process.kill()
	if not negate:
		if not err_found:
			raise AssertionError("Didn't receive expected string " + exp_error)
	else:
		if err_found:
			raise AssertionError("Receive expected unexpected string " + exp_error)
	return first_line

def test_vf_to_vf_vip_dnat(capsys, add_machine, build_path):
	d = multiprocessing.Process(name = "sniffer", target = vf_to_vf_tcp_vf1_responder)
	d.daemon=False
	d.start()

	expected_str = ul_actual_src
	add_vip_test = build_path+"/test/dp_grpc_client --addvip " + vm2_name + " --ipv4 " + virtual_ip
	eval_cmd_output(add_vip_test, expected_str)
	time.sleep(1)

	# vm1 (vf0) -> vm2 (vf2), vm2 has VIP, send packet to VIP from vm1 side, whether the packet is received 
	# and sent back by vm2 (DNAT)
	tcp_pkt = Ether(dst = vf1_mac, src = vf0_mac, type = 0x0800) / IP(dst = virtual_ip, src = vf0_ip) / TCP(sport=1200)
	sendp(tcp_pkt, iface = vf0_tap)
	
	pkt_list = sniff(count = 1, lfilter = is_tcp_pkt, iface = vf0_tap, timeout = 2)
	if len(pkt_list) == 0:
		raise AssertionError('Cannot receive tcp reply via VIP (DNAT)!')

	expected_str = "Delvip"
	del_vip_test = build_path+"/test/dp_grpc_client --delvip " + vm2_name
	eval_cmd_output(del_vip_test, expected_str)

def test_vf_to_pf_vip_snat(capsys, add_machine, build_path):
	d = multiprocessing.Process(name = "sniffer1", target = encaped_tcp_in_ipv6_vip_responder, args=(pf0_tap,))
	d.daemon=False
	d.start()

	d2 = multiprocessing.Process(name = "sniffer2", target = encaped_tcp_in_ipv6_vip_responder, args=(pf1_tap,))
	d2.daemon=False
	d2.start()

	expected_str = ul_actual_src
	add_vip_test = build_path+"/test/dp_grpc_client --addvip " + vm2_name + " --ipv4 " + virtual_ip
	eval_cmd_output(add_vip_test, expected_str)
	time.sleep(1)

	# vm2 (vf1) -> PF0/PF1 (internet traffic), vm2 has VIP, check on PFs side, whether VIP is source (SNAT)
	tcp_pkt = Ether(dst = pf0_mac, src = vf1_mac, type = 0x0800) / IP(dst = public_ip, src = vf1_ip) / TCP(sport=1240)
	sendp(tcp_pkt, iface = vf1_tap)
	
	pkt_list = sniff(count = 1, lfilter = is_tcp_pkt, iface = vf1_tap, timeout = 5)
	if len(pkt_list) == 0:
		raise AssertionError('Cannot receive tcp reply via VIP (SNAT)!')

	expected_str = "Delvip"
	del_vip_test = build_path+"/test/dp_grpc_client --delvip " + vm2_name
	eval_cmd_output(del_vip_test, expected_str)

def send_tcp_pkt_from_vm1():

	# sys.stdout = open(str(os.getpid()) + ".out", "w")
	pkt_list = sniff(count=1,lfilter=is_tcp_pkt,iface=pf0_tap,timeout=10)

	if len(pkt_list)==0:
		raise AssertionError('Cannot receive network-natted tcp pkt on pf')

	pkt=pkt_list[0]
	pkt.show()

	if Ether in pkt:
		pktether=pkt[Ether]
	if IPv6 in pkt:
		pktipv6 = pkt[IPv6]
	if IP in pkt:
		pktip= pkt[IP]
	if TCP in pkt:
		pkttcp= pkt[TCP]

	if pktip.src == nat_vip and pkttcp.sport == nat_local_min_port:
		reply_pkt = Ether(dst=pktether.src, src=pktether.dst, type=0x86DD)/IPv6(dst=ul_actual_src, src=pktipv6.dst, nh=4)/IP(dst=pktip.src, src=pktip.dst) /TCP(sport=pkttcp.dport, dport=pkttcp.sport)
		time.sleep(1)
		sendp(reply_pkt, iface=pf0_tap)


def test_vf_to_pf_network_nat_tcp(capsys, add_machine, build_path):

	expected_str = "Addnat"
	add_net_nat_vm1_test = build_path+"/test/dp_grpc_client --addnat " + vm1_name + " --ipv4 " + nat_vip + " --min_port " + str(nat_local_min_port) + " --max_port "+ str(nat_local_max_port) 
	eval_cmd_output(add_net_nat_vm1_test, expected_str)

	d = multiprocessing.Process(name = "send_tcp_pkt", target = send_tcp_pkt_from_vm1, args=())
	d.daemon=False
	d.start()

	tcp_pkt = Ether(dst = pf0_mac, src = vf0_mac, type = 0x0800) / IP(dst = public_ip, src = vf0_ip) / TCP(sport=1240)
	time.sleep(2)
	sendp(tcp_pkt, iface = vf0_tap)

	pkt_list = sniff(count=1,lfilter=is_tcp_pkt,iface=vf0_tap,timeout=10)

	if len(pkt_list)==0:
		raise AssertionError('Cannot receive network-natted tcp pkt on pf')

	pkt=pkt_list[0]
	# pkt.show()
	
	if Ether in pkt:
		pktether=pkt[Ether]
	if IPv6 in pkt:
		pktipv6 = pkt[IPv6]
	if IP in pkt:
		pktip= pkt[IP]
	if TCP in pkt:
		pkttcp= pkt[TCP]

	if pktip.dst !=vf0_ip  or pkttcp.dport != 1240:
		raise AssertionError('Received wrong packet with ip:'+pktip.dst+" dport:"+ str(pkttcp.dport))

	expected_str = "Delnat"
	add_net_nat_vm1_test = build_path+"/test/dp_grpc_client --delnat " + vm1_name + " --ipv4 " + nat_vip 
	eval_cmd_output(add_net_nat_vm1_test, expected_str)

def send_icmp_pkt_from_vm1():

	pkt_list = sniff(count=1,lfilter=is_icmp_pkt,iface=pf0_tap,timeout=10)

	if len(pkt_list)==0:
		raise AssertionError('Cannot receive network-natted tcp pkt on pf')

	pkt=pkt_list[0]

	if Ether in pkt:
		pktether=pkt[Ether]
	if IPv6 in pkt:
		pktipv6 = pkt[IPv6]
	if IP in pkt:
		pktip= pkt[IP]
	if ICMP in pkt:
		pkticmp= pkt[ICMP]

	if pktip.src == nat_vip:
		reply_pkt = Ether(dst=pktether.src, src=pktether.dst, type=0x86DD)/IPv6(dst=ul_actual_src, src=pktipv6.dst, nh=4)/IP(dst=pktip.src, src=pktip.dst) / ICMP(type=0, id=pkticmp.id)
		sendp(reply_pkt, iface=pf0_tap)

def test_vf_to_pf_network_nat_icmp(capsys, add_machine, build_path):

	expected_str = "Addnat"
	add_net_nat_vm1_test = build_path+"/test/dp_grpc_client --addnat " + vm1_name + " --ipv4 " + nat_vip + " --min_port " + str(nat_local_min_port) + " --max_port "+ str(nat_local_max_port) 
	eval_cmd_output(add_net_nat_vm1_test, expected_str)

	d = multiprocessing.Process(name = "send_icmp_pkt", target = send_icmp_pkt_from_vm1, args=())
	d.daemon=False
	d.start()
	time.sleep(1)
	icmp_pkt = Ether(dst = pf0_mac, src = vf0_mac, type = 0x0800) / IP(dst = public_ip, src = vf0_ip) / ICMP(type=8, id=0x0040)
	sendp(icmp_pkt, iface = vf0_tap)

	pkt_list = sniff(count=1,lfilter=is_icmp_pkt,iface=vf0_tap,timeout=3)

	if len(pkt_list)==0:
		raise AssertionError('Cannot receive network-natted icmp pkt on pf')

	pkt=pkt_list[0]
	
	if Ether in pkt:
		pktether=pkt[Ether]
	if IPv6 in pkt:
		pktipv6 = pkt[IPv6]
	if IP in pkt:
		pktip= pkt[IP]
	if ICMP in pkt:
		pkticmp= pkt[ICMP]

	if pktip.dst !=vf0_ip:
		raise AssertionError('Received wrong icmp packet with ip:'+pktip.dst)

	expected_str = "Delnat"
	add_net_nat_vm1_test = build_path+"/test/dp_grpc_client --delnat " + vm1_name + " --ipv4 " + nat_vip 
	eval_cmd_output(add_net_nat_vm1_test, expected_str)

def send_bounce_pkt_to_pf():
	bouce_pkt = Ether(dst=mc_mac, src=pf0_mac, type=0x86DD)/IPv6(dst=ul_actual_dst, src=ul_actual_src, nh=4)/IP(dst=nat_vip, src=public_ip) /TCP(sport=8989, dport=510)
	time.sleep(3)
	sendp(bouce_pkt, iface=pf0_tap)

def send_lb_pkt_to_pf():
	lb_pkt = Ether(dst=mc_mac, src=pf0_mac, type=0x86DD)/IPv6(dst=ul_actual_src, src=ul_actual_dst, nh=4)/IP(dst=virtual_ip, src=public_ip) /TCP(sport=1234, dport=80)
	time.sleep(3)
	sendp(lb_pkt, iface=pf0_tap)

def test_network_nat_pkt_relay(capsys, add_machine, build_path):
	expected_str = "Addnat"
	add_net_nat_vm1_test = build_path+"/test/dp_grpc_client --addnat " + vm1_name + " --ipv4 " + nat_vip + " --min_port " + str(nat_local_min_port) + " --max_port "+ str(nat_local_max_port) 
	eval_cmd_output(add_net_nat_vm1_test, expected_str)

	expected_str = "AddNeighNat"
	add_net_nat_vm1_test = build_path+"/test/dp_grpc_client --addneighnat " + " --ipv4 " + nat_vip + " --vni " + vni + " --min_port " + str(nat_neigh_min_port) + " --max_port "+ str(nat_neigh_max_port) + " --t_ipv6 "+nat_neigh_ul_dst
	eval_cmd_output(add_net_nat_vm1_test, expected_str)

	d = multiprocessing.Process(name = "send_bounce_pkt", target = send_bounce_pkt_to_pf, args=())
	d.daemon=False
	d.start()

	# answer, unanswered = srp(bouce_pkt, iface=pf0_tap, timeout=10)
	pkt_list = sniff(count=2,lfilter=is_tcp_pkt,iface=pf0_tap,timeout=10)

	if len(pkt_list)<2:
		raise AssertionError('Cannot receive network-natted relay pkt on pf')
	# it seems that pkt_list[0] is the injected pkt
	pkt=pkt_list[1]

	if Ether in pkt:
		pktether=pkt[Ether]
	if IPv6 in pkt:
		pktipv6 = pkt[IPv6]
	if IP in pkt:
		pktip= pkt[IP]
	if TCP in pkt:
		pkttcp= pkt[TCP]
	if pktipv6.dst != nat_neigh_ul_dst  or pkttcp.dport != 510:
		raise AssertionError('Received wrong network-nat relayed packet with outer dst ipv6 addr:'+pktipv6.dst+" dport:"+ pkttcp.dport)

	expected_str = "DelNeighNat"
	add_net_nat_vm1_test = build_path+"/test/dp_grpc_client --delneighnat " + " --ipv4 " + nat_vip + " --vni " + vni + " --min_port " + str(nat_neigh_min_port) + " --max_port "+ str(nat_neigh_max_port)
	eval_cmd_output(add_net_nat_vm1_test, expected_str)

	expected_str = "Delnat"
	add_net_nat_vm1_test = build_path+"/test/dp_grpc_client --delnat " + vm1_name + " --ipv4 " + nat_vip
	eval_cmd_output(add_net_nat_vm1_test, expected_str)


def test_pf_to_vf_network_lb_tcp(capsys, add_machine, build_path):
	expected_str = ul_actual_src
	add_lbvip_test = build_path+"/test/dp_grpc_client --createlb "+ mylb + " --vni " + vni + " --ipv4 " + virtual_ip + " --port 80 --protocol tcp" 
	eval_cmd_output(add_lbvip_test, expected_str)

	expected_str = ul_short_src
	add_pfx_test = build_path+"/test/dp_grpc_client --addlbpfx " + vm1_name + " --ipv4 " + virtual_ip + " --length 32"
	first_line = eval_cmd_output(add_pfx_test, expected_str)
	vm1_target_lb_pfx_underlay = first_line[26:]

	expected_str = "LB target added"
	add_lbvip_test = build_path+"/test/dp_grpc_client --addlbvip " + mylb + " --t_ipv6 " + vm1_target_lb_pfx_underlay
	eval_cmd_output(add_lbvip_test, expected_str)

	d = multiprocessing.Process(name = "send_lb_pkt", target = send_lb_pkt_to_pf, args=())
	d.daemon=False
	d.start()

	pkt_list = sniff(count=1,lfilter=is_tcp_pkt,iface=vf0_tap,timeout=7)

	if len(pkt_list)==0:
		raise AssertionError('Cannot receive loadbalanced tcp pkt on vf')

	pkt=pkt_list[0]
	# pkt.show()
	
	if Ether in pkt:
		pktether=pkt[Ether]
	if IP in pkt:
		pktip= pkt[IP]
	if TCP in pkt:
		pkttcp= pkt[TCP]

	if pktip.dst != virtual_ip  or pkttcp.dport != 80:
		raise AssertionError('Received wrong packet with ip:'+pktip.dst+" dport:"+ str(pkttcp.dport))

	expected_str = "DelLBprefix"
	del_pfx_test = build_path+"/test/dp_grpc_client --dellbpfx " + vm1_name + " --ipv4 " + virtual_ip + " --length 32"
	eval_cmd_output(del_pfx_test, expected_str)

	expected_str = "Delete LB Success"
	del_lbvip_test = build_path+"/test/dp_grpc_client --dellb " + mylb
	eval_cmd_output(del_lbvip_test, expected_str)


def test_grpc_addmachine_error_102(capsys, build_path):
	# Try to add using an existing vm identifier
	expected_error_str = "error 102"
	add_machine_test = build_path+"/test/dp_grpc_client --addmachine " + vm2_name + " --vni "+ vni + " --ipv4 " + vf1_ip + " --ipv6 " + vf1_ipv6
	eval_cmd_output(add_machine_test, expected_error_str)

def test_grpc_getmachine_single(capsys, build_path):
	# Try to get a single existing interface(machine)
	expected_str = vf1_ip
	add_machine_test = build_path+"/test/dp_grpc_client --getmachine " + vm2_name
	eval_cmd_output(add_machine_test, expected_str)

def test_grpc_addmachine_error_106(capsys, build_path):
	# Try to add with new machine identifer but already given IPv4
	expected_error_str = "error 106"
	add_machine_test = build_path+"/test/dp_grpc_client --addmachine " + vm3_name + " --vni "+ vni + " --ipv4 " + vf1_ip + " --ipv6 " + vf1_ipv6
	eval_cmd_output(add_machine_test, expected_error_str)

def test_grpc_delmachine_error_151(capsys, build_path):
	# Try to delete with machine identifer which doesnt exist
	expected_str = "error 151"
	del_machine_test = build_path+"/test/dp_grpc_client --delmachine " + vm3_name
	eval_cmd_output(del_machine_test, expected_str)

def test_grpc_add_list_delmachine(capsys, build_path):
	# Try to add a new machine, list it, delete it and confirm the deletion with list again
	expected_str = "net_tap4"
	add_machine_test = build_path+"/test/dp_grpc_client --addmachine " + vm3_name+ " --vni "+ vni + " --ipv4 " + vf2_ip + " --ipv6 " + vf2_ipv6
	eval_cmd_output(add_machine_test, expected_str)

	expected_str = vm3_name
	list_machine_test = build_path+"/test/dp_grpc_client --getmachines "
	eval_cmd_output(list_machine_test, expected_str)

	expected_str = "Delmachine"
	del_machine_test = build_path+"/test/dp_grpc_client --delmachine " + vm3_name
	eval_cmd_output(del_machine_test, expected_str)

	expected_str = vm3_name
	list_machine_test = build_path+"/test/dp_grpc_client --getmachines "
	eval_cmd_output(list_machine_test, expected_str, negate=True)

def test_grpc_addroute_error_251(capsys, build_path):
	# Try to add a route which is already added
	expected_str = "error 251"
	add_route_test = build_path+"/test/dp_grpc_client --addroute --vni " + vni + " --ipv4 " + ov_target_pfx + " --length 24 --t_vni " + vni + " --t_ipv6 2a10:afc0:e01f:f408::1"
	eval_cmd_output(add_route_test, expected_str)

def test_grpc_list_delroutes(capsys, build_path):
	# Try to list routes, delete one of them, list and add again
	expected_str = ov_target_pfx
	list_route_test = build_path+"/test/dp_grpc_client --listroutes --vni " + vni
	eval_cmd_output(list_route_test, expected_str)

	expected_str = "Delroute"
	del_route_test = build_path+"/test/dp_grpc_client --delroute --vni " + vni + " --ipv4 " + ov_target_pfx + " --length 24"
	eval_cmd_output(del_route_test, expected_str)

	expected_str = ov_target_pfx
	list_route_test = build_path+"/test/dp_grpc_client --listroutes --vni " + vni
	eval_cmd_output(list_route_test, expected_str, negate=True)

	expected_str = "error"
	add_route_test = build_path+"/test/dp_grpc_client --addroute --vni " + vni + " --ipv4 " + ov_target_pfx + " --length 24 --t_vni " + vni + " --t_ipv6 2a10:afc0:e01f:f408::1"
	eval_cmd_output(add_route_test, expected_str, negate=True)

def test_grpc_add_list_delVIP(capsys, build_path):
	# Try to add VIP, list, test error cases, delete vip and list again
	expected_str = ul_actual_src
	add_vip_test = build_path+"/test/dp_grpc_client --addvip " + vm2_name + " --ipv4 " + virtual_ip
	eval_cmd_output(add_vip_test, expected_str)

	expected_str = virtual_ip
	get_vip_test = build_path+"/test/dp_grpc_client --getvip " + vm2_name
	eval_cmd_output(get_vip_test, expected_str)

	# Try to add the same vip again
	expected_str = "351"
	add_vip_test = build_path+"/test/dp_grpc_client --addvip " + vm2_name + " --ipv4 " + virtual_ip
	eval_cmd_output(add_vip_test, expected_str)

	# Try to add to a machine which doesnt exist
	expected_str = "350"
	add_vip_test = build_path+"/test/dp_grpc_client --addvip " + vm3_name + " --ipv4 " + virtual_ip
	eval_cmd_output(add_vip_test, expected_str)

	expected_str = "Delvip"
	del_vip_test = build_path+"/test/dp_grpc_client --delvip " + vm2_name
	eval_cmd_output(del_vip_test, expected_str)

	expected_str = virtual_ip
	get_vip_test = build_path+"/test/dp_grpc_client --getvip " + vm2_name
	eval_cmd_output(get_vip_test, expected_str, negate=True)

def test_grpc_add_list_delLBVIP(capsys, build_path):
	# Try to add LB VIP, list, test error cases, delete vip and list again
	expected_str = ul_actual_src
	add_lbvip_test = build_path+"/test/dp_grpc_client --createlb "+ mylb + " --vni " + vni + " --ipv4 " + virtual_ip + " --port 80 --protocol tcp" 
	eval_cmd_output(add_lbvip_test, expected_str)

	expected_str = "LB target added"
	add_lbvip_test = build_path+"/test/dp_grpc_client --addlbvip " + mylb + " --t_ipv6 " + back_ip1
	eval_cmd_output(add_lbvip_test, expected_str)

	expected_str = back_ip1
	list_backips_test = build_path+"/test/dp_grpc_client --listbackips " + mylb
	eval_cmd_output(list_backips_test, expected_str)

	expected_str = "LB target added"
	add_lbvip_test = build_path+"/test/dp_grpc_client --addlbvip " + mylb + " --t_ipv6 " + back_ip2
	eval_cmd_output(add_lbvip_test, expected_str)

	expected_str = back_ip2
	list_backips_test = build_path+"/test/dp_grpc_client --listbackips " + mylb
	eval_cmd_output(list_backips_test, expected_str)

	expected_str = "Dellbvip"
	del_lbvip_test = build_path+"/test/dp_grpc_client --dellbvip " + mylb + " --t_ipv6 " + back_ip1
	eval_cmd_output(del_lbvip_test, expected_str)

	expected_str = back_ip1
	list_backips_test = build_path+"/test/dp_grpc_client --listbackips " + mylb
	eval_cmd_output(list_backips_test, expected_str, negate=True)

	expected_str = "Dellbvip"
	del_lbvip_test = build_path+"/test/dp_grpc_client --dellbvip " + mylb + " --t_ipv6 " + back_ip2
	eval_cmd_output(del_lbvip_test, expected_str)

	expected_str = back_ip2
	list_backips_test = build_path+"/test/dp_grpc_client --listbackips " + mylb
	eval_cmd_output(list_backips_test, expected_str, negate=True)

	expected_str = ul_actual_src
	del_lbvip_test = build_path+"/test/dp_grpc_client --getlb " + mylb
	eval_cmd_output(del_lbvip_test, expected_str)

	expected_str = "Delete LB Success"
	del_lbvip_test = build_path+"/test/dp_grpc_client --dellb " + mylb
	eval_cmd_output(del_lbvip_test, expected_str)

def test_grpc_add_list_delPfx(capsys, build_path):
	# Try to add Prefix, list, test error cases, delete prefix and list again
	expected_str = ul_actual_src
	add_pfx_test = build_path+"/test/dp_grpc_client --addpfx " + vm2_name + " --ipv4 " + pfx_ip + " --length 24"
	eval_cmd_output(add_pfx_test, expected_str)

	expected_str = pfx_ip
	list_pfx_test = build_path+"/test/dp_grpc_client --listpfx " + vm2_name
	eval_cmd_output(list_pfx_test, expected_str)

	# Try to add the same pfx again
	expected_str = "652"
	add_pfx_test = build_path+"/test/dp_grpc_client --addpfx " + vm2_name + " --ipv4 " + pfx_ip + " --length 24"
	eval_cmd_output(add_pfx_test, expected_str)

	# Try to add/delete to/from a machine which doesnt exist
	expected_str = "651"
	add_pfx_test = build_path+"/test/dp_grpc_client --addpfx " + vm3_name + " --ipv4 " + pfx_ip + " --length 24"
	eval_cmd_output(add_pfx_test, expected_str)

	expected_str = "701"
	del_pfx_test = build_path+"/test/dp_grpc_client --delpfx " + vm3_name + " --ipv4 " + pfx_ip + " --length 24"
	eval_cmd_output(del_pfx_test, expected_str)

	expected_str = "Delprefix"
	del_pfx_test = build_path+"/test/dp_grpc_client --delpfx " + vm2_name + " --ipv4 " + pfx_ip + " --length 24"
	eval_cmd_output(del_pfx_test, expected_str)

	expected_str = pfx_ip
	list_pfx_test = build_path+"/test/dp_grpc_client --listpfx " + vm2_name
	eval_cmd_output(list_pfx_test, expected_str, negate=True)

def test_grpc_add_list_delLoadBalancerTargets(capsys, build_path):
	# Try to add Prefix, list, test error cases, delete prefix and list again
	expected_str = ul_short_src
	add_pfx_test = build_path+"/test/dp_grpc_client --addlbpfx " + vm2_name + " --ipv4 " + pfx_ip + " --length 32"
	eval_cmd_output(add_pfx_test, expected_str)

	expected_str = pfx_ip
	list_pfx_test = build_path+"/test/dp_grpc_client --listlbpfx " + vm2_name
	eval_cmd_output(list_pfx_test, expected_str)

	# Try to add/delete to/from a machine which doesnt exist
	expected_str = "651"
	add_pfx_test = build_path+"/test/dp_grpc_client --addlbpfx " + vm3_name + " --ipv4 " + pfx_ip + " --length 32"
	eval_cmd_output(add_pfx_test, expected_str)

	expected_str = "701"
	del_pfx_test = build_path+"/test/dp_grpc_client --dellbpfx " + vm3_name + " --ipv4 " + pfx_ip + " --length 32"
	eval_cmd_output(del_pfx_test, expected_str)

	expected_str = "DelLBprefix"
	del_pfx_test = build_path+"/test/dp_grpc_client --dellbpfx " + vm2_name + " --ipv4 " + pfx_ip + " --length 32"
	eval_cmd_output(del_pfx_test, expected_str)

	expected_str = pfx_ip
	list_pfx_test = build_path+"/test/dp_grpc_client --listpfx " + vm2_name
	eval_cmd_output(list_pfx_test, expected_str, negate=True)

# def test_grpc_add_list_del_routes_big_reply(capsys, build_path):
# 	expected_str = "Listroute called"
# 	pfx_first = "192.168."
# 	pfx_second = 29
# 	max_lines = MAX_LINES_ROUTE_REPLY + 2 + 1
# 	for idx in range(MAX_LINES_ROUTE_REPLY):
# 		pfx_second = pfx_second + 1
# 		ov_target_pfx = pfx_first + str(pfx_second) + ".0"
# 		add_ipv4_route_cmd = build_path+"/test/dp_grpc_client --addroute --vni " + vni + " --ipv4 " + ov_target_pfx + " --length 32 --t_vni " + t_vni + " --t_ipv6 " + ul_actual_dst
# 		subprocess.run(shlex.split(add_ipv4_route_cmd), stdout=subprocess.DEVNULL)
# 	list_route_test = build_path + "/test/dp_grpc_client --listroutes --vni " + vni
# 	#TODO this test case is not complete and needs to handle more than 38 lines
# 	eval_cmd_output(list_route_test, expected_str, maxlines=max_lines)
# 	pfx_first = "192.168."
# 	pfx_second = 29
# 	for idx in range(MAX_LINES_ROUTE_REPLY):
# 		pfx_second = pfx_second + 1
# 		ov_target_pfx = pfx_first + str(pfx_second) + ".0"
# 		del_route_test = build_path+"/test/dp_grpc_client --delroute --vni " + vni + " --ipv4 " + ov_target_pfx + " --length 32"
#		subprocess.run(shlex.split(del_route_test), stdout=subprocess.DEVNULL)
