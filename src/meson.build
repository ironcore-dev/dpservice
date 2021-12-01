dp_sources = ['dp_service.cpp', 'dp_port.c', 'dpdk_layer.c', 'nodes/arp_node.c',
			  'nodes/drop_node.c', 'nodes/rx_node.c', 'nodes/cls_node.c','nodes/dhcp_node.c','nodes/dhcpv6_node.c',
			  'nodes/arp_node.c','nodes/ipv6_nd_node.c', 'nodes/tx_node.c', 'nodes/ipv4_lookup_node.c', 'nodes/l2_decap_node.c',
			  'dp_mbuf_dyn.c', 'dp_lpm.c', 'nodes/ipv6_encap_node.c', 'nodes/geneve_encap_node.c',
			  'nodes/ipv6_lookup_node.c', 'nodes/ipv6_decap_node.c', 'nodes/geneve_decap_node.c', 'dp_util.c', 
			  '../proto/dpdk.grpc.pb.cc', '../proto/dpdk.pb.cc', 'dp_grpc_service.cpp']

executable('dp_service', dp_sources, include_directories : [inc, proto_inc],
			dependencies : [dpdk_dep, proto_dep, grpc_dep, grpccpp_dep, thread_dep] )
