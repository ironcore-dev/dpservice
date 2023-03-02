dp_sources = ['dp_service.c', 'dp_port.c', 'dpdk_layer.c', 'dp_nat.c', 'dp_lb.c', 'dp_vnf.c', 'dp_multi_path.c','nodes/arp_node.c',
			  'nodes/drop_node.c', 'nodes/rx_node.c','nodes/rx_periodic_node.c', 'nodes/cls_node.c','nodes/dhcp_node.c','nodes/dhcpv6_node.c',
			  'nodes/arp_node.c','nodes/ipv6_nd_node.c', 'nodes/tx_node.c', 'nodes/ipv4_lookup_node.c', 'nodes/l2_decap_node.c',
			  'dp_mbuf_dyn.c', 'dp_lpm.c', 'nodes/ipv6_encap_node.c', 'nodes/firewall_node.c',
			  'nodes/ipv6_lookup_node.c', 'nodes/geneve_tunnel_node.c', 'nodes/common_node.c',
			  'nodes/overlay_switch_node.c','nodes/ipip_tunnel_node.c','dp_util.c','dp_conf.c','dp_periodic_msg.c',
			  'nodes/conntrack_node.c', 'nodes/dnat_node.c', 'nodes/packet_relay_node.c','nodes/lb_node.c',
			  'nodes/snat_node.c', 'grpc/dp_grpc_service.cpp', 'grpc/dp_async_grpc.cpp', 'grpc/dp_grpc_impl.c', 'dp_flow.c',
			  'dp_netlink.c','rte_flow/dp_rte_flow.c','rte_flow/dp_rte_flow_init.c','rte_flow/dp_rte_flow_traffic_forward.c',
			  'monitoring/dp_monitoring.c','monitoring/dp_event.c',
			  'dp_log.c', 'dp_error.c', 'dp_hairpin.c', 'dp_telemetry.c', 'grpc/dp_grpc_thread.cpp'
 			]
# TODO(plague) look into autogereration of such dependencies (source file list)
if get_option('enable_virtual_services')
	dp_sources += [ 'nodes/virtsvc_node.c', 'dp_virtsvc.c' ]
endif

exe = executable('dp_service', [dp_sources, grpc_generated], include_directories : [inc],
			dependencies : [dpdk_dep, proto_dep, grpc_dep, grpccpp_dep, thread_dep, libuuid_dep] )

if get_option('enable_usermode')
custom_target('dp_service_user', depends: exe, input: exe, output: 'dp_service_user',
  command: [ '../hack/set_cap.sh', '@INPUT@', '@OUTPUT@' ],
  build_by_default: true,
  console: true
)
endif
