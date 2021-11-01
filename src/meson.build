dp_sources = ['dp_service.c', 'dp_port.c', 'dpdk_layer.c', 'nodes/arp_node.c',
			  'nodes/drop_node.c', 'nodes/rx_node.c', 'nodes/cls_node.c', 
			  'nodes/arp_node.c', 'nodes/tx_node.c', 'nodes/ipv4_lookup_node.c',
			  'dp_mbuf_dyn.c']

executable('dp_service', dp_sources, include_directories : inc,
            dependencies : dpdk_dep)
