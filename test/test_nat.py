import multiprocessing

from config import *
from helpers import *


def test_network_nat_external_icmp_echo(add_machine, request_ip_vf0, build_path):

	expected_str = "Addnat"
	add_net_nat_vm1_test = build_path+"/test/dp_grpc_client --addnat " + vm1_name + " --ipv4 " + nat_vip + " --min_port " + str(nat_local_min_port) + " --max_port "+ str(nat_local_max_port)
	eval_cmd_output(add_net_nat_vm1_test, expected_str)

	icmp_pkt = (Ether(dst=mc_mac, src=pf0_mac, type=0x86DD) /
			    IPv6(dst=ul_actual_dst, src=ul_actual_src, nh=4) /
			    IP(dst=nat_vip, src=public_ip) /
			    ICMP(type=8, id=0x0040))
	answer = srp1(icmp_pkt, iface=pf0_tap, timeout=2)
	assert answer and is_icmp_pkt(answer)

	expected_str = "Delnat"
	add_net_nat_vm1_test = build_path+"/test/dp_grpc_client --delnat " + vm1_name
	eval_cmd_output(add_net_nat_vm1_test, expected_str)


def send_bounce_pkt_to_pf():
	bouce_pkt = (Ether(dst=mc_mac, src=pf0_mac, type=0x86DD) /
				 IPv6(dst=ul_actual_dst, src=ul_actual_src, nh=4) /
				 IP(dst=nat_vip, src=public_ip) /
				 TCP(sport=8989, dport=510))
	time.sleep(3)
	sendp(bouce_pkt, iface=pf0_tap)

def test_network_nat_pkt_relay(add_machine, build_path):

	expected_str = "Addnat"
	add_net_nat_vm1_test = build_path+"/test/dp_grpc_client --addnat " + vm1_name + " --ipv4 " + nat_vip + " --min_port " + str(nat_local_min_port) + " --max_port "+ str(nat_local_max_port)
	eval_cmd_output(add_net_nat_vm1_test, expected_str)

	expected_str = "AddNeighNat"
	add_net_nat_vm1_test = build_path+"/test/dp_grpc_client --addneighnat " + " --ipv4 " + nat_vip + " --vni " + vni + " --min_port " + str(nat_neigh_min_port) + " --max_port " + str(nat_neigh_max_port) + " --t_ipv6 " + nat_neigh_ul_dst
	eval_cmd_output(add_net_nat_vm1_test, expected_str)

	multiprocessing.Process(name="send_bounce_pkt", target=send_bounce_pkt_to_pf, daemon=False).start()

	# answer, unanswered = srp(bouce_pkt, iface=pf0_tap, timeout=10)
	pkt_list = sniff(count=2,lfilter=is_tcp_pkt,iface=pf0_tap,timeout=10)
	assert len(pkt_list) == 2

	# it seems that pkt_list[0] is the injected pkt
	pkt = pkt_list[1]

	if Ether in pkt:
		pktether = pkt[Ether]
	if IPv6 in pkt:
		pktipv6 = pkt[IPv6]
	if IP in pkt:
		pktip = pkt[IP]
	if TCP in pkt:
		pkttcp = pkt[TCP]
	assert pktipv6.dst == nat_neigh_ul_dst and pkttcp.dport == 510, 'Received wrong network-nat relayed packet with outer dst ipv6 addr:'+pktipv6.dst+" dport:"+pkttcp.dport

	expected_str = nat_vip
	get_net_nat_local_vm1_test = build_path+"/test/dp_grpc_client --getnat " + vm1_name
	eval_cmd_output(get_net_nat_local_vm1_test, expected_str)

	expected_str = nat_neigh_ul_dst
	get_net_nat_neigh_vm1_test = build_path+"/test/dp_grpc_client --getnatinfo neigh "  + " --ipv4 " + nat_vip
	eval_cmd_output(get_net_nat_neigh_vm1_test, expected_str)

	expected_str = "DelNeighNat"
	add_net_nat_vm1_test = build_path+"/test/dp_grpc_client --delneighnat " + " --ipv4 " + nat_vip + " --vni " + vni + " --min_port " + str(nat_neigh_min_port) + " --max_port " + str(nat_neigh_max_port)
	eval_cmd_output(add_net_nat_vm1_test, expected_str)

	expected_str = "Delnat"
	add_net_nat_vm1_test = build_path+"/test/dp_grpc_client --delnat " + vm1_name
	eval_cmd_output(add_net_nat_vm1_test, expected_str)

	expected_str = nat_vip
	get_net_nat_local_vm1_test =  build_path+"/test/dp_grpc_client --getnat " + vm1_name
	eval_cmd_output(get_net_nat_local_vm1_test, expected_str, negate=True)

	expected_str = nat_neigh_ul_dst
	get_net_nat_neigh_vm1_test = build_path+"/test/dp_grpc_client --getnatinfo neigh "  + " --ipv4 " + nat_vip
	eval_cmd_output(get_net_nat_neigh_vm1_test, expected_str, negate=True)

	expected_str = "374"
	add_net_nat_vm1_test = build_path+"/test/dp_grpc_client --delneighnat " + " --ipv4 " + nat_vip + " --vni " + vni + " --min_port " + str(nat_neigh_min_port) + " --max_port " + str(nat_neigh_max_port)
	eval_cmd_output(add_net_nat_vm1_test, expected_str)

	expected_str = "362"
	add_net_nat_vm1_test = build_path+"/test/dp_grpc_client --delnat " + vm1_name
	eval_cmd_output(add_net_nat_vm1_test, expected_str)
