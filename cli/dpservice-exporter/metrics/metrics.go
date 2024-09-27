// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

const SocketPath = "/var/run/dpdk/rte/dpdk_telemetry.v2"

func queryTelemetry(conn net.Conn, log *logrus.Logger, command string, response interface{}) {
	_, err := conn.Write([]byte(command))
	if err != nil {
		log.Errorf("Failed to send command to %s: %v", SocketPath, err)
		return
	}

	respBytes := make([]byte, 1024*6)
	var responseBuffer bytes.Buffer
	for {
		n, err := conn.Read(respBytes)
		if err != nil {
			log.Errorf("Failed to read response from %s: %v", SocketPath, err)
			return
		}
		responseBuffer.Write(respBytes[:n])
		parts := strings.SplitN(command, ",", 2)
		command = parts[0]
		if bytes.Contains(respBytes, []byte(command)) {
			break
		}
	}

	err = json.Unmarshal(responseBuffer.Bytes(), response)
	if err != nil {
		log.Errorf("Failed to unmarshal JSON response: %v", err)
	}
}

func Update(conn net.Conn, hostname string, log *logrus.Logger) {
	var ealHeapList EalHeapList
	queryTelemetry(conn, log, "/eal/heap_list", &ealHeapList)

	for _, id := range ealHeapList.Value {
		var ealHeapInfo EalHeapInfo
		queryTelemetry(conn, log, fmt.Sprintf("/eal/heap_info,%d", id), &ealHeapInfo)
		for key, value := range ealHeapInfo.Value {
			// Only export metrics of type float64 (/eal/heap_info contains also some string values)
			if v, ok := value.(float64); ok {
				HeapInfo.With(prometheus.Labels{"node_name": hostname, "info": key}).Set(v)
			}
		}
	}

	var ethdevList EthdevList
	queryTelemetry(conn, log, "/ethdev/list", &ethdevList)

	for _, id := range ethdevList.Value {
		var ethdevInfo EthdevInfo
		queryTelemetry(conn, log, fmt.Sprintf("/ethdev/info,%d", id), &ethdevInfo)

		var ethdevXstats EthdevXstats
		queryTelemetry(conn, log, fmt.Sprintf("/ethdev/xstats,%d", id), &ethdevXstats)

		for statName, statValueFloat := range ethdevXstats.Value {
			InterfaceStat.With(prometheus.Labels{"interface": ethdevInfo.Value.Name, "stat_name": statName}).Set(statValueFloat)
		}
	}
	var dpserviceNatPort DpServiceNatPort
	queryTelemetry(conn, log, "/dp_service/nat/used_port_count", &dpserviceNatPort)
	for ifName, portCount := range dpserviceNatPort.Value {
		InterfaceStat.With(prometheus.Labels{"interface": ifName, "stat_name": "nat_used_port_count"}).Set(float64(portCount))
	}

	var dpserviceVirtsvcPort DpServiceVirtsvcPort
	queryTelemetry(conn, log, "/dp_service/virtsvc/used_port_count", &dpserviceVirtsvcPort)
	for ifName, portCount := range dpserviceVirtsvcPort.Value {
		InterfaceStat.With(prometheus.Labels{"interface": ifName, "stat_name": "virtsvc_used_port_count"}).Set(float64(portCount))
	}

	var dpserviceFirewallRuleCount DpServiceFirewallRuleCount
	queryTelemetry(conn, log, "/dp_service/firewall/rule_count", &dpserviceFirewallRuleCount)
	for ifName, fwRuleCount := range dpserviceFirewallRuleCount.Value {
		InterfaceStat.With(prometheus.Labels{"interface": ifName, "stat_name": "firewall_rule_count"}).Set(float64(fwRuleCount))
	}

	var dpserviceCallCount DpServiceGraphCallCount
	queryTelemetry(conn, log, "/dp_service/graph/call_count", &dpserviceCallCount)

	for graphNodeName, callCount := range dpserviceCallCount.GraphCallCnt.Node_0_to_255 {
		CallCount.With(prometheus.Labels{"node_name": hostname, "graph_node": graphNodeName}).Set(callCount)
	}

	var dpServiceHashTableSaturation DpServiceHashTableSaturation
	queryTelemetry(conn, log, "/dp_service/table/saturation", &dpServiceHashTableSaturation)

	for table, saturation := range dpServiceHashTableSaturation.Value {
		HashTableSaturation.With(prometheus.Labels{"table_name": table, "stat_name": "capacity"}).Set(saturation.Capacity)
		HashTableSaturation.With(prometheus.Labels{"table_name": table, "stat_name": "entries"}).Set(saturation.Entries)
	}
}
