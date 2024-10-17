// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	DpdkEthdevErrors = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dpdk_ethdev_errors_total",
			Help: "DPDK total ethdev errors",
		},
		[]string{"name", "stat"},
	)

	DpdkEthdevPackets = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dpdk_ethdev_packets_total",
			Help: "DPDK total ethdev packets",
		},
		[]string{"name", "stat"},
	)

	DpdkEthdevBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dpdk_ethdev_bytes_total",
			Help: "DPDK total ethdev bytes",
		},
		[]string{"name", "stat"},
	)

	DpdkEthdevMisc = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dpdk_ethdev_misc",
			Help: "Other DPDK ethdev statistics",
		},
		[]string{"name", "stat"},
	)

	DpdkEthdevLinkStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dpdk_ethdev_link_status",
			Help: "Link status of DPDK ethdev",
		},
		[]string{"name"},
	)

	DpdkHeapInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dpdk_heap_info",
			Help: "Dpservice heap info",
		},
		[]string{"node", "info"},
	)

	DpserviceUsedNatPortsCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dps_nat_used_ports_count",
			Help: "Count of used NAT ports on interface",
		},
		[]string{"interface_id"},
	)

	DpserviceFwRulesCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dps_firewall_rules_count",
			Help: "Count of firewall rules on interface",
		},
		[]string{"interface_id"},
	)

	DpserviceVirtsvcUsedPortsCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dps_virtsvc_used_ports_count",
			Help: "Count of used virtual service ports",
		},
		[]string{"address"},
	)

	DpserviceCallCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dps_graph_call_count",
			Help: "Dpservice graph statistics",
		},
		[]string{"node", "graph_node"},
	)

	DpserviceHashTableSaturation = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dps_hash_table_saturation",
			Help: "Dpservice hash table saturation",
		},
		[]string{"table", "stat"},
	)
)

type EthdevList struct {
	Value []int `json:"/ethdev/list"`
}

type EthdevInfo struct {
	Value struct {
		Name string `json:"name"`
	} `json:"/ethdev/info"`
}

type EthdevLinkStatus struct {
	Value struct {
		Duplex string `json:"duplex,omitempty"`
		Speed  int    `json:"speed,omitempty"`
		Status string `json:"status,omitempty"`
	} `json:"/ethdev/link_status"`
}

type EthdevXstats struct {
	Value map[string]float64 `json:"/ethdev/xstats"`
}

type DpServiceNatPortCount struct {
	Value map[string]int `json:"/dp_service/nat/used_port_count"`
}

type DpServiceVirtsvcPortCount struct {
	Value map[string]int `json:"/dp_service/virtsvc/used_port_count"`
}

type DpServiceFirewallRuleCount struct {
	Value map[string]int `json:"/dp_service/firewall/rule_count"`
}

type NodeData map[string]float64

type GraphCallCount struct {
	Node_0_to_255 NodeData `json:"Node_0_to_255"`
}

type DpServiceGraphCallCount struct {
	GraphCallCnt GraphCallCount `json:"/dp_service/graph/call_count"`
}

type EalHeapList struct {
	Value []int `json:"/eal/heap_list"`
}

type EalHeapInfo struct {
	Value map[string]any `json:"/eal/heap_info"`
}

type DpServiceHashTableSaturation struct {
	Value map[string]HashTable `json:"/dp_service/table/saturation"`
}

type HashTable struct {
	Capacity float64 `json:"capacity"`
	Entries  float64 `json:"entries"`
}
