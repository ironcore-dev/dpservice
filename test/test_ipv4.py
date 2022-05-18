from scapy.all import *
from scapy.layers.l2 import ARP
from scapy.layers.inet import Ether
from scapy.layers.dhcp import *
from scapy.config import conf

import pytest, shlex, subprocess, time
from config import *

import multiprocessing
import signal

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

def is_icmp_pkt(pkt):
	if ICMP in pkt:
		return True
	return False

def is_tcp_pkt(pkt):
	if TCP in pkt:
		return True
	return False

def ipv4_in_ipv6_responder():
	pkt_list = sniff(count=1,lfilter=is_encaped_icmp_pkt,iface=pf0_tap)
	pkt=pkt_list[0]
	pkt.show()
	if Ether in pkt:
		pktether=pkt[Ether]
	if IPv6 in pkt:
		pktipv6 = pkt[IPv6]
	if IP in pkt:
		pktip= pkt[IP]

	reply_pkt = Ether(dst=pktether.src,src=pktether.dst,type=0x86DD)/IPv6(dst=ul_actual_src,src=ul_target_ipv6,nh=4)/IP(dst=pktip.src,src=pktip.dst)/ICMP(type=0)
	time.sleep(1)
	sendp(reply_pkt, iface=pf0_tap)


def test_IPv4inIPv6(capsys,add_machine):
	d=multiprocessing.Process(name="sniffer",target=ipv4_in_ipv6_responder)
	d.daemon=False
	d.start()

	time.sleep(1)

	icmp_echo_pkt = Ether(dst=pf0_mac,src=vf0_mac,type=0x0800)/IP(dst="192.168.129.5",src="172.32.10.5")/ICMP(type=8)
	sendp(icmp_echo_pkt,iface=vf0_tap)
	
	pkt_list = sniff(count=1,lfilter=is_icmp_pkt,iface=vf0_tap,timeout=2)
	if len(pkt_list)==0:
		raise AssertionError('Cannot receive icmp reply!')
	

def vf_to_vf_tcp_responder():
	pkt_list = sniff(count=1,lfilter=is_tcp_pkt,iface=vf1_tap)
	pkt=pkt_list[0]
	pkt.show()
	if Ether in pkt:
		pktether=pkt[Ether]
	if IP in pkt:
		pktip= pkt[IP]

	reply_pkt = Ether(dst=pktether.src,src=pktether.dst,type=0x0800)/IP(dst=pktip.src,src=pktip.dst)/TCP()
	time.sleep(1)
	sendp(reply_pkt, iface=vf1_tap)


def test_vf_to_vf_tcp(capsys,add_machine):
	d=multiprocessing.Process(name="sniffer",target=vf_to_vf_tcp_responder)
	d.daemon=False
	d.start()

	time.sleep(1)

	tcp_pkt = Ether(dst=vf1_mac,src=vf0_mac,type=0x0800)/IP(dst=vf1_ip,src=vf0_ip)/TCP()
	sendp(tcp_pkt,iface=vf0_tap)
	
	pkt_list = sniff(count=1,lfilter=is_tcp_pkt,iface=vf0_tap,timeout=2)
	if len(pkt_list)==0:
		raise AssertionError('Cannot receive icmp reply!')

def eval_cmd_output(cmd_str, exp_error, negate=False, maxlines=5):
	cmd = shlex.split(cmd_str)
	process = subprocess.Popen(cmd, 
								stdout=subprocess.PIPE,
								universal_newlines=True)
	count = 0
	err_found = False
	while count < maxlines:
		output = process.stdout.readline()
		line = output.strip()
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

def test_grpc_addmachine_error_102(capsys, build_path):
	# Try to add using an existing vm identifier
	expected_error_str = "error 102"
	add_machine_test = build_path+"/test/dp_grpc_client --addmachine " + vm2_name + " --vni "+ vni + " --ipv4 " + vf1_ip + " --ipv6 " + vf1_ipv6
	eval_cmd_output(add_machine_test, expected_error_str)

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
	expected_str = "Addvip"
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
	# Try to add VIP, list, test error cases, delete vip and list again
	expected_str = "Addlbvip"
	add_lbvip_test = build_path+"/test/dp_grpc_client --addlbvip --vni " + vni + " --ipv4 " + virtual_ip + " --back_ip " + back_ip1
	eval_cmd_output(add_lbvip_test, expected_str)

	expected_str = back_ip1
	list_backips_test = build_path+"/test/dp_grpc_client --listbackips --vni " + vni + " --ipv4 " + virtual_ip
	eval_cmd_output(list_backips_test, expected_str)

	expected_str = "Addlbvip"
	add_lbvip_test = build_path+"/test/dp_grpc_client --addlbvip --vni " + vni + " --ipv4 " + virtual_ip + " --back_ip " + back_ip2
	eval_cmd_output(add_lbvip_test, expected_str)

	expected_str = back_ip2
	list_backips_test = build_path+"/test/dp_grpc_client --listbackips --vni " + vni + " --ipv4 " + virtual_ip
	eval_cmd_output(list_backips_test, expected_str)

	# Add to non existent VNI
	expected_str = "551"
	add_lbvip_test = build_path+"/test/dp_grpc_client --addlbvip --vni " + "400" + " --ipv4 " + virtual_ip + " --back_ip " + back_ip2
	eval_cmd_output(add_lbvip_test, expected_str)

	expected_str = "Dellbvip"
	del_lbvip_test = build_path+"/test/dp_grpc_client --dellbvip --vni " + vni + " --ipv4 " + virtual_ip + " --back_ip " + back_ip1
	eval_cmd_output(del_lbvip_test, expected_str)

	expected_str = back_ip1
	list_backips_test = build_path+"/test/dp_grpc_client --listbackips --vni " + vni + " --ipv4 " + virtual_ip
	eval_cmd_output(list_backips_test, expected_str, negate=True)

	expected_str = "Dellbvip"
	del_lbvip_test = build_path+"/test/dp_grpc_client --dellbvip --vni " + vni + " --ipv4 " + virtual_ip + " --back_ip " + back_ip2
	eval_cmd_output(del_lbvip_test, expected_str)

	expected_str = back_ip2
	list_backips_test = build_path+"/test/dp_grpc_client --listbackips --vni " + vni + " --ipv4 " + virtual_ip
	eval_cmd_output(list_backips_test, expected_str, negate=True)

def test_grpc_add_list_delPfx(capsys, build_path):
	# Try to add VIP, list, test error cases, delete vip and list again
	expected_str = "Addprefix"
	add_pfx_test = build_path+"/test/dp_grpc_client --addpfx " + vm2_name + " --ipv4 " + pfx_ip + " --length 24"
	eval_cmd_output(add_pfx_test, expected_str)

	expected_str = pfx_ip
	list_pfx_test = build_path+"/test/dp_grpc_client --listpfx " + vm2_name
	eval_cmd_output(list_pfx_test, expected_str)

	# Try to add the same pfx again
	expected_str = "652"
	add_pfx_test = build_path+"/test/dp_grpc_client --addpfx " + vm2_name + " --ipv4 " + pfx_ip + " --length 24"
	eval_cmd_output(add_pfx_test, expected_str)

	# Try to add to a machine which doesnt exist
	expected_str = "651"
	add_pfx_test = build_path+"/test/dp_grpc_client --addpfx " + vm3_name + " --ipv4 " + pfx_ip + " --length 24"
	eval_cmd_output(add_pfx_test, expected_str)