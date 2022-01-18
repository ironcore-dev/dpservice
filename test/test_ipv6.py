from scapy.all import *
from scapy.layers.l2 import ARP
from scapy.layers.inet6 import *
from scapy.layers.dhcp import *
from scapy.config import conf

import pytest, shlex, subprocess, time
from config import *

@pytest.fixture()
def add_machine(build_path):
	add_machine_cmd = build_path+"/test/dp_grpc_client --addmachine 1 --vni 100 --ipv6 2001::10"
	subprocess.run(shlex.split("ip link set dev "+vf0_tap+" up"))
	subprocess.run(shlex.split(add_machine_cmd))
	time.sleep(1)

def test_nd(add_machine):
    answer = neighsol(gw_ip6, vf0_ipv6, iface=vf0_tap, timeout=2)
    mac = str(answer[ICMPv6NDOptDstLLAddr].lladdr)
    print(mac)
    assert(mac == vf0_mac)

def test_dhcp6(capsys,add_machine):
    eth = Ether(dst=mc_mac)
    ip6 = IPv6(dst=gw_ip6)
    udp = UDP(sport=546,dport=547)
    sol = DHCP6_Solicit()
    req = DHCP6_Request()
    
    sol.trid = random.randint(0,16777215)
    rc_op = DHCP6OptRapidCommit(optlen=0)
    opreq = DHCP6OptOptReq()
    et_op= DHCP6OptElapsedTime()
    cid_op = DHCP6OptClientId()
    iana_op = DHCP6OptIA_NA(iaid=0x18702501)

    iana_op.optlen = 12
    iana_op.T1 = 0
    iana_op.T2 = 0
    cid_op.optlen = 28
    cid_op.duid = "00020000ab11b7d4e0eed266171d"
    opreq.optlen = 4

    pkt = eth/ip6/udp/sol/iana_op/rc_op/et_op/cid_op/opreq
    answer = srp1(pkt, iface=vf0_tap, type=ETH_P_IPV6, timeout=2)
    print(str(answer[DHCP6OptIAAddress].addr))
    pytest.assume(str(cid_op.duid) == str(answer[DHCP6OptClientId].duid))

    iana_op = answer[DHCP6OptIAAddress]
    pkt = eth/ip6/udp/req/iana_op/rc_op/et_op/cid_op/opreq
    answer = srp1(pkt, iface=vf0_tap, type=ETH_P_IPV6, timeout=2)
    pytest.assume(str(cid_op.duid) == str(answer[DHCP6OptClientId].duid))
    print(str(answer[DHCP6OptIAAddress].addr))
    assert(str(answer[DHCP6OptIAAddress].addr) == vf0_ipv6)







