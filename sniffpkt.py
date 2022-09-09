from scapy.all import *

pf0_mac = "90:3c:b3:33:72:fb"
vf0_mac = "66:73:20:a9:a7:00"
public_ip = "45.86.6.6"
vf0_ip ="176.44.33.12"
vf0_tap = "dtapvf_0"
pf0_tap = "dtap0"
pf1_tap = "dtap1"
ul_actual_src="2a10:afc0:e01f:f403:0:64::"

extern_ipv4 = "45.88.77.66"

def sniff_simulate_pkt():
	pkt_list = sniff(count=1,lfilter=is_tcp_pkt,iface=pf1_tap,timeout=60)
	if len(pkt_list)==0:
		return 

	pkt=pkt_list[0]
	pkt.show()

	# if Ether in pkt:
	# 	pktether=pkt[Ether]
	# if IPv6 in pkt:
	# 	pktipv6 = pkt[IPv6]
	# if IP in pkt:
	# 	pktip= pkt[IP]
	# if TCP in pkt:
	# 	pkttcp = pkt[TCP]

	# reply_pkt = Ether(dst=pktether.src, src=pktether.dst, type=0x86DD)/IPv6(dst=ul_actual_src, src=pktipv6.dst, nh=4)/IP(dst=pktip.src, src=pktip.dst) /TCP(sport=pkttcp.dport, dport=pkttcp.sport)
	# time.sleep(1)
	# # sendp(reply_pkt, iface=pf0_tap)
	
	# bouce_pkt = Ether(dst=pktether.src, src=pktether.dst, type=0x86DD)/IPv6(dst=ul_actual_src, src=pktipv6.dst, nh=4)/IP(dst=extern_ipv4, src=pktip.dst) /TCP(sport=pkttcp.dport, dport=2100)
	# sendp(bouce_pkt, iface=pf0_tap)
	# pkt_list = sniff(count=1,lfilter=is_tcp_pkt,iface=pf0_tap,timeout=60)
	# if len(pkt_list)==0:
	# 	return 

	# pkt=pkt_list[0]
	# pkt.show()

def is_tcp_pkt(pkt):
	if TCP in pkt:
		return True
	return False


if __name__ == "__main__":
	sniff_simulate_pkt()