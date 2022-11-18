from config import *
from helpers import *


def test_network_lb_external_icmp_echo(capsys, add_machine, request_ip_vf0, build_path):

	expected_str = ul_actual_src
	add_lbvip_test = build_path+"/test/dp_grpc_client --createlb " + mylb + " --vni " + vni + " --ipv4 " + virtual_ip + " --port 80 --protocol tcp"
	eval_cmd_output(add_lbvip_test, expected_str)

	icmp_pkt = (Ether(dst=mc_mac, src=pf0_mac, type=0x86DD) /
				IPv6(dst=ul_actual_dst, src=ul_actual_src, nh=4) /
				IP(dst=virtual_ip, src=public_ip) /
				ICMP(type=8, id=0x0040))
	answer = srp1(icmp_pkt, iface=pf0_tap, timeout=2)
	assert answer and is_icmp_pkt(answer)

	expected_str = "Delete LB Success"
	del_lbvip_test = build_path+"/test/dp_grpc_client --dellb " + mylb
	eval_cmd_output(del_lbvip_test, expected_str)
