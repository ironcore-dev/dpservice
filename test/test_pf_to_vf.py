import multiprocessing

from config import *
from helpers import *


def send_lb_pkt_to_pf():
	lb_pkt = (Ether(dst=mc_mac, src=pf0_mac, type=0x86DD) /
			  IPv6(dst=ul_actual_dst, src=ul_actual_src, nh=4) /
			  IP(dst=virtual_ip, src=public_ip) /
			  TCP(sport=1234, dport=80))
	time.sleep(3)
	sendp(lb_pkt, iface=pf0_tap)

def test_pf_to_vf_lb_tcp(add_machine, build_path):

	expected_str = ul_actual_src
	add_lbvip_test = build_path+"/test/dp_grpc_client --createlb " + mylb + " --vni " + vni + " --ipv4 " + virtual_ip + " --port 80 --protocol tcp"
	eval_cmd_output(add_lbvip_test, expected_str)

	expected_str = ul_short_src
	add_pfx_test = build_path+"/test/dp_grpc_client --addlbpfx " + vm1_name + " --ipv4 " + virtual_ip + " --length 32"
	first_line = eval_cmd_output(add_pfx_test, expected_str)
	vm1_target_lb_pfx_underlay = first_line[26:]

	expected_str = "LB target added"
	add_lbvip_test = build_path+"/test/dp_grpc_client --addlbvip " + mylb + " --t_ipv6 " + vm1_target_lb_pfx_underlay
	eval_cmd_output(add_lbvip_test, expected_str)

	multiprocessing.Process(name="send_lb_pkt", target=send_lb_pkt_to_pf, daemon=False).start()

	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=vf0_tap, timeout=7)
	assert len(pkt_list) == 1

	pkt = pkt_list[0]

	if Ether in pkt:
		pktether = pkt[Ether]
	if IP in pkt:
		pktip = pkt[IP]
	if TCP in pkt:
		pkttcp = pkt[TCP]

	assert pktip.dst == virtual_ip and pkttcp.dport == 80, \
		'Received wrong packet with ip:'+pktip.dst+" dport:"+str(pkttcp.dport)

	expected_str = "DelLBprefix"
	del_pfx_test = build_path+"/test/dp_grpc_client --dellbpfx " + vm1_name + " --ipv4 " + virtual_ip + " --length 32"
	eval_cmd_output(del_pfx_test, expected_str)

	expected_str = "Delete LB Success"
	del_lbvip_test = build_path+"/test/dp_grpc_client --dellb " + mylb
	eval_cmd_output(del_lbvip_test, expected_str)
