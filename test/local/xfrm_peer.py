# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import os
import select
import shlex
import subprocess
import warnings

from scapy.all import ETH_P_IPV6, AsyncSniffer, Ether, IPv6, Raw, raw, sendp

from config import *
from helpers import is_esp_pkt, run_command

# The ethernet header the relay replaces; everything past it is carried unchanged
ether_hdr_len = 14


def _run_quiet(cmd):
	# For probing and for cleaning up, where a command failing is an answer rather than an error
	return subprocess.run(shlex.split(cmd),
						  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


# The neighbouring instance, played by the Linux kernel rather than by scapy inside the test
# process. IpsecPeer proves dpservice interoperates with a second implementation of ESP; this
# one proves it interoperates with *the* implementation it would meet in production, which is
# a different claim - the kernel refuses frames scapy would happily accept, and it builds its
# own from a configuration written the way a real deployment writes it.
#
# The peer is a second neighbour, entirely separate from the one IpsecPeer plays: its own
# underlay /64, its own overlay prefix, its own key material, and an SPI of its own for what
# dpservice sends it. What it sends *under* is on purpose the number the scapy peer sends under:
# see config.py for what each of those choices is worth.
#
# Everything it needs lives in one network namespace, which is what makes it cleanable: a run
# that dies anywhere leaves exactly one named object behind, and deleting it takes the veth,
# the xfrm interface, the associations and the policies with it.
class XfrmPeer:

	# Probed before anything is created, so that a kernel without XFRM interfaces skips the test
	# instead of failing halfway through setting one up. Returns the reason to skip, or None.
	@staticmethod
	def probe():
		probe_iface = "dpsxfrmprobe"

		_run_quiet(f"ip link del {probe_iface}")
		if not _run_quiet(f"ip link add {probe_iface} type xfrm dev lo if_id 1"):
			return ("XFRM interfaces are unavailable:"
					" needs a kernel with CONFIG_XFRM_INTERFACE (4.19+) and iproute2 4.19+")
		_run_quiet(f"ip link del {probe_iface}")
		return None

	# The VM the peer talks to. Its underlay address is where the answers have to be addressed:
	# ipip_decap picks the receiving port by that address alone and never looks inside.
	def __init__(self, vm):
		self.vm = vm
		self.echo = None
		self.relays = []

	def start(self):
		self._clean_leftovers()
		self._create_namespace()
		self._create_associations()
		self._start_echo_server()
		self._start_relays()

	def stop(self):
		for relay in self.relays:
			if relay.running:
				relay.stop()
		self.relays = []

		if self.echo:
			self.echo.terminate()
			self.echo.wait()
			self.echo = None

		_run_quiet(f"ip netns del {xfrm_ns}")
		# only reachable if setup failed before the veth was moved into the namespace
		_run_quiet(f"ip link del {xfrm_veth_host}")

	# Every counter in xfrm_stat is an error counter, and the namespace was created for this
	# test alone, so anything non-zero is a packet the kernel dropped - and named, which is the
	# whole reason to read the file. A silent drop inside xfrm is otherwise indistinguishable
	# from a packet that was never sent.
	def errors(self):
		stat = run_command(f"ip netns exec {xfrm_ns} cat /proc/net/xfrm_stat").decode()
		counters = [line.split() for line in stat.splitlines()]
		return {name: int(count) for name, count in counters if int(count) != 0}

	@staticmethod
	def _ns(cmd):
		return run_command(f"ip netns exec {xfrm_ns} {cmd}")

	# What a previous run can have left behind.
	def _clean_leftovers(self):
		if xfrm_ns in run_command("ip netns list").decode().split():
			# Whatever still lives in the namespace goes first, and that is not tidiness:
			# `ip netns del` removes the *name*, not the namespace, for as long as a process
			# still has it open. A leftover echo server would keep the old namespace and the
			# veth inside it alive, invisibly, right next to the new namespace of the same name.
			#
			# Found by what it holds rather than by what its command line says: a pattern
			# matched against `ps` kills everything that merely mentions the script, an editor
			# or a grep for it included.
			for pid in run_command(f"ip netns pids {xfrm_ns}").decode().split():
				warnings.warn(f"A previous run left process {pid} in the {xfrm_ns} namespace, killed it")
				_run_quiet(f"kill -9 {pid}")
			warnings.warn(f"A previous run left the {xfrm_ns} namespace behind, removed it")
			run_command(f"ip netns del {xfrm_ns}")

		# either a namespace that died before the veth was moved into it, or one a killed
		# process still holds open - deleting this end takes the one inside it either way
		if _run_quiet(f"ip link show {xfrm_veth_host}"):
			warnings.warn(f"A previous run left the {xfrm_veth_host} interface behind, removed it")
			run_command(f"ip link del {xfrm_veth_host}")

	def _create_namespace(self):
		run_command(f"ip netns add {xfrm_ns}")
		run_command(f"ip link add {xfrm_veth_host} address {xfrm_veth_host_mac}"
					f" type veth peer name {xfrm_veth_peer} address {xfrm_veth_peer_mac}")
		run_command(f"ip link set {xfrm_veth_peer} netns {xfrm_ns}")
		# the host end carries nothing but what the relay puts on it, and must answer none of it
		run_command(f"sysctl -w net.ipv6.conf.{xfrm_veth_host}.disable_ipv6=1")
		run_command(f"ip link set {xfrm_veth_host} up")

		# nothing answers a neighbour solicitation on this link, so duplicate address detection
		# would only cost the addresses their first second of life
		self._ns("sysctl -w net.ipv6.conf.all.accept_dad=0")
		self._ns(f"ip link set {xfrm_veth_peer} up")
		self._ns(f"ip -6 addr add {xfrm_peer_ul_ipv6}/64 dev {xfrm_veth_peer} nodad")
		self._ns(f"ip -6 route add {xfrm_local_ul_prefix} dev {xfrm_veth_peer}")
		# and for the same reason the VM's underlay address is resolved here rather than asked
		# for: the relay is not a host and answers nothing, it only carries frames
		self._ns(f"ip -6 neigh add {self.vm.ul_ipv6} lladdr {xfrm_veth_host_mac}"
				 f" dev {xfrm_veth_peer} nud permanent")

		# The tenant's own interface: if_id is what binds it to the policies below, and a
		# decrypted packet surfaces here rather than on the underlay interface.
		self._ns(f"ip link add {xfrm_iface} type xfrm dev {xfrm_veth_peer} if_id {xfrm_if_id}")
		self._ns(f"ip link set {xfrm_iface} up")
		self._ns(f"ip addr add {xfrm_peer_ov_ip}/32 dev {xfrm_iface}")
		self._ns(f"ip route add {xfrm_vm_ov_ip_route} dev {xfrm_iface}")

	# The two associations and the two policies, mirroring what dp_service.py installs over gRPC
	# - what dpservice calls its egress association is this side's inbound state, and the keys
	# have to line up that way round or every frame fails its ICV check.
	#
	# `flag af-unspec` is not decoration. Without it the kernel pins the association's selector
	# family to the outer header's, IPv6 here, and the tunnelled IPv4 is dropped with nothing
	# logged - XfrmOutNoStates on the way out, which is why errors() exists.
	#
	# `mode tunnel` is what the peer is told, while dpservice frames ESP in transport mode over
	# an outer header it built itself. That the two agree is the interoperability claim in
	# docs/concepts/ipsec.md, tested here rather than asserted.
	def _create_associations(self):
		self._ns(f"ip xfrm state add src {self.vm.ul_ipv6} dst {xfrm_peer_ul_ipv6}"
				 f" proto esp spi {xfrm_spi_egress} reqid {xfrm_reqid} mode tunnel if_id {xfrm_if_id}"
				 f" flag af-unspec replay-window {ipsec_replay_window}"
				 f" aead 'rfc4106(gcm(aes))' 0x{xfrm_key_egress}{xfrm_salt_egress} 128"
				 f" sel src {xfrm_vm_ov_ip_route} dst {xfrm_peer_ov_ip_route}")
		self._ns(f"ip xfrm state add src {xfrm_peer_ul_ipv6} dst {self.vm.ul_ipv6}"
				 f" proto esp spi {xfrm_spi_ingress} reqid {xfrm_reqid} mode tunnel if_id {xfrm_if_id}"
				 f" flag af-unspec"
				 f" aead 'rfc4106(gcm(aes))' 0x{xfrm_key_ingress}{xfrm_salt_ingress} 128")

		self._ns(f"ip xfrm policy add dir in if_id {xfrm_if_id}"
				 f" src {xfrm_vm_ov_ip_route} dst {xfrm_peer_ov_ip_route}"
				 f" tmpl src {self.vm.ul_ipv6} dst {xfrm_peer_ul_ipv6}"
				 f" proto esp reqid {xfrm_reqid} mode tunnel")
		self._ns(f"ip xfrm policy add dir out if_id {xfrm_if_id}"
				 f" src {xfrm_peer_ov_ip_route} dst {xfrm_vm_ov_ip_route}"
				 f" tmpl src {xfrm_peer_ul_ipv6} dst {self.vm.ul_ipv6}"
				 f" proto esp reqid {xfrm_reqid} mode tunnel")

	def _start_echo_server(self):
		script = f"{os.path.dirname(os.path.abspath(__file__))}/{xfrm_echo_script}"
		cmd = f"ip netns exec {xfrm_ns} python3 -u {script} {xfrm_peer_ov_ip} {xfrm_echo_port}"

		print(cmd)
		self.echo = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE)
		# see xfrm_echo.py for what this line is worth
		if not select.select([self.echo.stdout], [], [], xfrm_echo_timeout)[0] \
				or self.echo.stdout.readline().strip() != b"listening":
			raise AssertionError("Echo server did not start listening")

	# What dpservice sends the peer leaves the PF addressed to whatever neighbouring router
	# netlink found, and on a TAP it never finds one - so the destination MAC is all zeroes.
	# No bridge can deliver such a frame to a kernel stack: it arrives as PACKET_OTHERHOST and
	# is dropped before xfrm ever sees it, and no valid MAC can be assigned to make it match.
	# The frames are therefore carried across by hand, with the ethernet header rewritten and
	# everything past it passed on byte for byte.
	def _start_relays(self):
		self.relays = [
			self._relay(PF0.tap, xfrm_veth_host, self._is_to_peer,
						Ether(dst=xfrm_veth_peer_mac, src=xfrm_veth_host_mac, type=ETH_P_IPV6)),
			self._relay(xfrm_veth_host, PF0.tap, self._is_to_dpservice,
						Ether(dst=PF0.mac, src=PF0.mac, type=ETH_P_IPV6)),
		]
		for relay in self.relays:
			relay.start()

	# The ethernet type has to be named: what follows the header the relay writes is raw bytes,
	# and a header built over those alone would go out as 0x9000 and be dropped by the receiving
	# stack before anything looked at what it carried.
	@staticmethod
	def _relay(src_iface, dst_iface, accept, ether_hdr):
		def forward(pkt):
			# rebuilt from the raw bytes rather than from scapy's dissection of them: what is
			# authenticated has to arrive exactly as it was sent, and a relay that re-encodes
			# ESP would be testing scapy's encoder instead of the two implementations
			sendp(ether_hdr / Raw(raw(pkt)[ether_hdr_len:]), iface=dst_iface, verbose=False)

		return AsyncSniffer(iface=src_iface, lfilter=accept, prn=forward, store=False)

	# Only this peer's own traffic is carried. Everything else on the PF belongs to another
	# test, and the suite's other peer is answered by scapy as it always was.
	@staticmethod
	def _is_to_peer(pkt):
		return is_esp_pkt(pkt) and pkt[IPv6].dst == xfrm_peer_ul_ipv6

	# The frames this relay injects are seen on the veth as well as the ones coming out of the
	# namespace, so the source address is what tells the peer's answers from its own echo.
	@staticmethod
	def _is_to_dpservice(pkt):
		return is_esp_pkt(pkt) and pkt[IPv6].src == xfrm_peer_ul_ipv6
