from scapy.all import *
from scapy.layers.l2 import ARP
from scapy.layers.inet import Ether

import pytest, shlex, subprocess, time

pf0_tap = "dtap0"
pf1_tap = "dtap1"
pf0_mac = "90:3c:b3:33:72:fb"
pf1_mac = "90:3c:b3:33:72:fc"
vf0_mac = "66:73:20:a9:a7:00"
vf0_tap = "dtapvf_0"
vf_patt = "dtapvf_"
ul_ipv6 = "2a10:afc0:e01f:f4::2"
start_str = "DPDK main loop started"

bcast_mac = "ff:ff:ff:ff:ff:ff"
null_ip = "0.0.0.0"
gw_ip4 = "169.254.0.1"


@pytest.fixture
def prepare_env(request, build_path):
	dp_service_cmd = build_path+"/src/dp_service -l 0,1 --vdev=net_tap0,iface="+pf0_tap+",mac=\""+pf0_mac+"\" "\
		"--vdev=net_tap1,iface="+pf1_tap+",mac=\""+pf1_mac+"\" --vdev=net_tap2,iface="+vf0_tap+",mac=\""+vf0_mac+"\"   -- "\
		"--pf0="+pf0_tap+" --pf1="+pf1_tap+" --vf-pattern="+vf_patt+" --ipv6="+ul_ipv6+" --no-offload --no-stats"
	cmd = shlex.split(dp_service_cmd)

	process = subprocess.Popen(cmd, 
								stdout=subprocess.PIPE,
								universal_newlines=True)

	while True:
		output = process.stdout.readline()
		line = output.strip()
		if start_str in line:
			break
		return_code = process.poll()
		if return_code is not None:
			print('RETURN CODE', return_code)
			# Process has finished, read rest of the output 
			for output in process.stdout.readlines():
				print(output.strip())
			break
	def tear_down():
		process.terminate()
	request.addfinalizer(tear_down)
	return process



def test_l2_arp(prepare_env, build_path):
	return_code = prepare_env.poll()
	if return_code is not None:
		print("dp_service is not running")
		assert False
	
	try:
		add_machine_cmd = build_path+"/test/dp_grpc_client --addmachine 1 --vni 100 --ipv4 172.32.10.5"
		arp_packet = Ether(dst=bcast_mac)/ARP(pdst=gw_ip4, hwdst=vf0_mac, psrc=null_ip)

		subprocess.run(shlex.split("ip link set dev "+vf0_tap+" up"))
		subprocess.run(shlex.split(add_machine_cmd))
		time.sleep(1)
		answer, unanswered = srp(arp_packet, iface=vf0_tap, type=ETH_P_ARP, timeout=2)

		for sent, received in answer:
			assert (str(received[ARP].hwsrc) == vf0_mac)
		time.sleep(1)
	except Exception as e:
		prepare_env.terminate()
