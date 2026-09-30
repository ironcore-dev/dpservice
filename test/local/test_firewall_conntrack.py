# SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import pytest
import threading

from helpers import *

#
# Stateful firewall on top of conntrack
#
# Every test runs an exchange (request, reply, second request of the same flow) between a local VM and
# a peer, with firewall rules that only allow the original direction and block any new flow in the reverse one:
#  - a local initiating VM accepts the request in egress and has an ingress rule that matches nothing,
#  - a local responding VM accepts the request in ingress and has an egress rule that matches nothing.
# The reply can therefore only pass through the conntrack entry of the request, i.e. only if the reply key
# (including its VNF type) is exactly the key the reply packet produces when it arrives.
# The rule hit counters show how often the rules were evaluated: once for the whole exchange, so the second
# request must also still match the original key.
# The counters are only up to date when the telemetry refresh interval is disabled (--fast-fwall-telemetry),
# otherwise only the exchange itself is checked.
#
# A "remote" peer is a VM behind another dpservice (non-default route) or the internet (default route),
# its packets are injected into PF0 as IP-in-IPv6.
#

fwall_remote_vm_ip = f"{neigh_vni1_ov_ip_prefix}.150"
fwall_responder_nat_min_port = 200
fwall_responder_nat_max_port = 202


class Tcp:
	proto = "tcp"

	def org_rule_match(port):
		return { "dst_port_min": port, "dst_port_max": port }

	def request(sport, dport, seq):
		return TCP(sport=sport, dport=dport, flags="S" if seq == 0 else "A")

	def reply(pkt):
		return TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="SA")

	def is_request(sport, dport):
		return lambda pkt: TCP in pkt and (sport is None or pkt[TCP].sport == sport) and pkt[TCP].dport == dport

	def is_reply(sport, dport):
		return lambda pkt: TCP in pkt and pkt[TCP].sport == dport and pkt[TCP].dport == sport

	def src_port(pkt):
		return pkt[TCP].sport

# The echo identifier takes the role of the source port, there is no destination port
class Icmp:
	proto = "icmp"

	def org_rule_match(port):
		return { "icmp_type": 8 }

	def request(sport, dport, seq):
		return ICMP(type=8, id=sport, seq=seq)

	def reply(pkt):
		return ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)

	def is_request(sport, dport):
		return lambda pkt: ICMP in pkt and pkt[ICMP].type == 8 and (sport is None or pkt[ICMP].id == sport)

	def is_reply(sport, dport):
		return lambda pkt: ICMP in pkt and pkt[ICMP].type == 0 and pkt[ICMP].id == sport

	def src_port(pkt):
		return pkt[ICMP].id


class VfEndpoint:
	def __init__(self, vm, peer_ip, peer_mac=PF0.mac, ipv6=False):
		self.vm = vm
		self.peer_ip = peer_ip
		self.peer_mac = peer_mac
		self.ipv6 = ipv6
		self.tap = vm.tap

	def packet(self, l4, dst_ip=None):
		dst_ip = dst_ip or self.peer_ip
		l3 = IPv6(dst=dst_ip, src=self.vm.ipv6) if self.ipv6 else IP(dst=dst_ip, src=self.vm.ip)
		return Ether(dst=self.peer_mac, src=self.vm.mac) / l3 / l4

	def filter(self, lfilter):
		if self.ipv6:
			return lambda pkt: IPv6 in pkt and IP not in pkt and lfilter(pkt)
		return lambda pkt: IP in pkt and IPv6 not in pkt and lfilter(pkt)

class PfEndpoint:
	def __init__(self, ip, peer_ip, ul_ipv6, peer_ul_ipv6):
		self.ip = ip
		self.peer_ip = peer_ip
		self.ul_ipv6 = ul_ipv6
		self.peer_ul_ipv6 = peer_ul_ipv6
		self.tap = PF0.tap

	def packet(self, l4, dst_ip=None):
		return (Ether(dst=ipv6_multicast_mac, src=PF0.mac) /
				IPv6(dst=self.peer_ul_ipv6, src=self.ul_ipv6) /
				IP(dst=dst_ip or self.peer_ip, src=self.ip) /
				l4)

	def filter(self, lfilter):
		return lambda pkt: is_ipip_pkt(pkt) and lfilter(pkt)


class FwallSetup:
	def __init__(self, grpc_client):
		self.grpc_client = grpc_client
		self.rules = []
		self.nats = []

	def add_nat(self, vm, min_port=nat_local_min_port, max_port=nat_local_max_port):
		nat_ul_ipv6 = self.grpc_client.addnat(vm.name, nat_vip, min_port, max_port)
		self.nats.append(vm)
		return nat_ul_ipv6

	def _add_rule(self, vm, rule_id, l4, ipv6, **kwargs):
		any_prefix = "::/0" if ipv6 else "0.0.0.0/0"
		kwargs.setdefault("src_prefix", any_prefix)
		kwargs.setdefault("dst_prefix", any_prefix)
		self.grpc_client.addfwallrule(vm.name, rule_id, proto=l4.proto, **kwargs)
		self.rules.append((vm, rule_id))

	def add_reply_block_rule(self, vm, l4, direction, ipv6=False):
		never_matching = "2001:db8::/32" if ipv6 else "1.2.3.4/16"
		prefix = "src_prefix" if direction == "ingress" else "dst_prefix"
		self._add_rule(vm, "ct-reply-block", l4, ipv6, direction=direction, **{ prefix: never_matching })

	def add_initiator_rules(self, vm, l4, port, ipv6=False):
		self._add_rule(vm, "ct-org-egress", l4, ipv6, direction="egress", **l4.org_rule_match(port))
		self.add_reply_block_rule(vm, l4, "ingress", ipv6)

	def add_responder_rules(self, vm, l4, port, ipv6=False):
		self._add_rule(vm, "ct-org-ingress", l4, ipv6, **l4.org_rule_match(port))
		self.add_reply_block_rule(vm, l4, "egress", ipv6)

	def cleanup(self):
		for vm, rule_id in reversed(self.rules):
			self.grpc_client.delfwallrule(vm.name, rule_id)
		for vm in reversed(self.nats):
			self.grpc_client.delnat(vm.name)

@pytest.fixture
def fwall_setup(grpc_client):
	setup = FwallSetup(grpc_client)
	yield setup
	setup.cleanup()


def send_and_sniff(pkt, send_tap, sniff_tap, lfilter):
	sniffed = {}
	def sniffer():
		pkt_list = sniff(count=1, iface=sniff_tap, lfilter=lfilter, timeout=sniff_timeout)
		sniffed["pkt"] = pkt_list[0] if pkt_list else None
	thread = threading.Thread(target=sniffer)
	thread.start()
	delayed_sendp(pkt, send_tap)
	thread.join()
	return sniffed["pkt"]

def get_src_ip(pkt):
	return pkt[IP].src if IP in pkt else pkt[IPv6].src

# Request, reply (to whatever source the responder sees) and a second request of the same flow
# Returns the first request as seen by the responder
def run_exchange(l4, initiator, responder, sport, dport, vms):
	def assert_delivered(pkt, what):
		# the message (querying the hits takes a while) is only evaluated on failure
		assert pkt is not None, \
			f"{what} was dropped (firewall rule hits: { {vm.name: get_fwall_rule_hits(vm) for vm in vms} })"

	request = send_and_sniff(initiator.packet(l4.request(sport, dport, 0)), initiator.tap, responder.tap,
							 responder.filter(l4.is_request(None, dport)))
	assert_delivered(request, "Request")

	reply = send_and_sniff(responder.packet(l4.reply(request), get_src_ip(request)), responder.tap, initiator.tap,
						   initiator.filter(l4.is_reply(sport, dport)))
	assert_delivered(reply, "Reply")

	second = send_and_sniff(initiator.packet(l4.request(sport, dport, 1)), initiator.tap, responder.tap,
							responder.filter(l4.is_request(l4.src_port(request), dport)))
	assert_delivered(second, "Second request")

	return request

def assert_evaluated_once(fast_fwall_telemetry, initiator=None, responder=None):
	if not fast_fwall_telemetry:
		return
	if initiator:
		hits = get_fwall_rule_hits(initiator)
		assert hits == { "ct-org-egress": 1, "ct-reply-block": 0 }, \
			f"Flow evaluated more than once on the initiator, conntrack key mismatch (hits: {hits})"
	if responder:
		hits = get_fwall_rule_hits(responder)
		assert hits == { "ct-org-ingress": 1, "ct-reply-block": 0 }, \
			f"Flow evaluated more than once on the responder, conntrack key mismatch (hits: {hits})"


l4_params = pytest.mark.parametrize("l4,ipv6", [(Tcp, False), (Icmp, False)], ids=["tcp", "icmp"])


#
# VM1 <-> VM2 on the same host (west-east, never translated)
#
@pytest.mark.parametrize("initiator_nat,responder_nat", [
	(False, False), (True, False), (False, True), (True, True),
], ids=["no_nat", "initiator_nat", "responder_nat", "both_nat"])
@pytest.mark.parametrize("l4,ipv6", [(Tcp, False), (Icmp, False), (Tcp, True)], ids=["tcp", "icmp", "tcp6"])
def test_fwall_conntrack_vf_to_vf(prepare_ipv4, fwall_setup, fast_fwall_telemetry, l4, ipv6, initiator_nat, responder_nat):
	sport = 41000 + 10*(2*(l4 is Icmp) + ipv6) + 2*initiator_nat + responder_nat
	dport = 8100
	if initiator_nat:
		fwall_setup.add_nat(VM1)
	if responder_nat:
		fwall_setup.add_nat(VM2, fwall_responder_nat_min_port, fwall_responder_nat_max_port)
	fwall_setup.add_initiator_rules(VM1, l4, dport, ipv6)
	fwall_setup.add_responder_rules(VM2, l4, dport, ipv6)

	initiator = VfEndpoint(VM1, VM2.ipv6 if ipv6 else VM2.ip, VM2.mac, ipv6)
	responder = VfEndpoint(VM2, VM1.ipv6 if ipv6 else VM1.ip, VM1.mac, ipv6)
	request = run_exchange(l4, initiator, responder, sport, dport, (VM1, VM2))
	assert get_src_ip(request) == (VM1.ipv6 if ipv6 else VM1.ip) and l4.src_port(request) == sport, \
		f"West-east traffic must not be translated (src ip: {get_src_ip(request)}, sport: {l4.src_port(request)})"

	assert_evaluated_once(fast_fwall_telemetry, initiator=VM1, responder=VM2)


#
# VM1 <-> PF <-> VM on another host (non-default route, west-east, never translated)
#
@pytest.mark.parametrize("vm_nat", [False, True], ids=["no_nat", "vm_nat"])
@pytest.mark.parametrize("remote_initiates", [False, True], ids=["vm_initiator", "remote_initiator"])
@l4_params
def test_fwall_conntrack_vf_to_remote_vf(prepare_ipv4, fwall_setup, fast_fwall_telemetry, port_redundancy, l4, ipv6, remote_initiates, vm_nat):
	if port_redundancy:
		pytest.skip("Port redundancy is not supported")
	vm_port = 42000 + 10*(l4 is Icmp) + 2*remote_initiates + vm_nat
	# unique as well, the remote port is the echo identifier when the remote side initiates ICMP
	remote_port = 8200 + 10*(l4 is Icmp) + 2*remote_initiates + vm_nat
	if vm_nat:
		fwall_setup.add_nat(VM1)

	vm = VfEndpoint(VM1, fwall_remote_vm_ip)
	remote = PfEndpoint(fwall_remote_vm_ip, VM1.ip, neigh_vni1_ul_ipv6, VM1.ul_ipv6)
	if remote_initiates:
		fwall_setup.add_responder_rules(VM1, l4, vm_port)
		run_exchange(l4, remote, vm, remote_port, vm_port, (VM1,))
		assert_evaluated_once(fast_fwall_telemetry, responder=VM1)
	else:
		fwall_setup.add_initiator_rules(VM1, l4, remote_port)
		request = run_exchange(l4, vm, remote, vm_port, remote_port, (VM1,))
		assert request[IP].src == VM1.ip and l4.src_port(request) == vm_port and request[IPv6].dst == neigh_vni1_ul_ipv6, \
			f"West-east traffic must not be translated (src ip: {request[IP].src}, sport: {l4.src_port(request)})"
		assert_evaluated_once(fast_fwall_telemetry, initiator=VM1)


#
# VM1 <-> PF <-> internet (default route, south-north, translated when VM1 has a NAT)
#
@pytest.mark.parametrize("vm_nat", [False, True], ids=["no_nat", "vm_nat"])
@l4_params
def test_fwall_conntrack_vf_to_internet(prepare_ipv4, fwall_setup, fast_fwall_telemetry, port_redundancy, l4, ipv6, vm_nat):
	if port_redundancy:
		pytest.skip("Port redundancy is not supported")
	vm_port = 43000 + 10*(l4 is Icmp) + vm_nat
	public_port = 8300
	reply_ul_ipv6 = fwall_setup.add_nat(VM1) if vm_nat else VM1.ul_ipv6
	fwall_setup.add_initiator_rules(VM1, l4, public_port)

	vm = VfEndpoint(VM1, public_ip)
	internet = PfEndpoint(public_ip, None, router_ul_ipv6, reply_ul_ipv6)
	request = run_exchange(l4, vm, internet, vm_port, public_port, (VM1,))
	if vm_nat:
		assert request[IP].src == nat_vip and nat_local_min_port <= l4.src_port(request) < nat_local_max_port, \
			f"South-north traffic not translated (src ip: {request[IP].src}, sport: {l4.src_port(request)})"
	else:
		assert request[IP].src == VM1.ip and l4.src_port(request) == vm_port, \
			f"South-north traffic translated without NAT (src ip: {request[IP].src}, sport: {l4.src_port(request)})"

	assert_evaluated_once(fast_fwall_telemetry, initiator=VM1)

# NAT64 translates the packet before the firewall evaluates it, so only the reply direction is guarded here
def test_fwall_conntrack_vf_to_internet_nat64(prepare_ipv4, fwall_setup, port_redundancy):
	if port_redundancy:
		pytest.skip("Port redundancy is not supported")
	vm_port = 43100
	public_port = 8300
	nat_ul_ipv6 = fwall_setup.add_nat(VM1)
	fwall_setup.add_reply_block_rule(VM1, Tcp, "ingress", ipv6=True)

	vm = VfEndpoint(VM1, public_nat64_ipv6, ipv6=True)
	internet = PfEndpoint(public_ip, None, router_ul_ipv6, nat_ul_ipv6)
	request = run_exchange(Tcp, vm, internet, vm_port, public_port, (VM1,))
	assert request[IP].src == nat_vip, \
		f"NAT64 traffic not translated (src ip: {request[IP].src})"
