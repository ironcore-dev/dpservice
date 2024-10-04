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

var SocketPath = "/var/run/dpdk/rte/dpdk_telemetry.v2"

func queryTelemetry(conn net.Conn, log *logrus.Logger, command string, response interface{}) error {
	_, err := conn.Write([]byte(command))
	if err != nil {
		log.Errorf("Failed to send command to %s: %v", SocketPath, err)
		return err
	}

	respBytes := make([]byte, 1024*6)
	var responseBuffer bytes.Buffer
	for {
		n, err := conn.Read(respBytes)
		if err != nil {
			log.Errorf("Failed to read response from %s: %v", SocketPath, err)
			return err
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
	return nil
}

func Update(conn net.Conn, hostname string, log *logrus.Logger) error {
	var ealHeapList EalHeapList
	err := queryTelemetry(conn, log, "/eal/heap_list", &ealHeapList)
	if err != nil {
		return fmt.Errorf("failed to query eal heap list: %v", err)
	}

	for _, id := range ealHeapList.Value {
		var ealHeapInfo EalHeapInfo
		err = queryTelemetry(conn, log, fmt.Sprintf("/eal/heap_info,%d", id), &ealHeapInfo)
		if err != nil {
			return fmt.Errorf("failed to query eal heap info: %v", err)
		}
		for key, value := range ealHeapInfo.Value {
			// Only export metrics of type float64 (/eal/heap_info contains also some string values)
			if v, ok := value.(float64); ok {
				DpdkHeapInfo.With(prometheus.Labels{"node": hostname, "info": key}).Set(v)
			}
		}
	}

	var ethdevList EthdevList
	err = queryTelemetry(conn, log, "/ethdev/list", &ethdevList)
	if err != nil {
		return err
	}
	for _, id := range ethdevList.Value {
		var ethdevInfo EthdevInfo
		err = queryTelemetry(conn, log, fmt.Sprintf("/ethdev/info,%d", id), &ethdevInfo)
		if err != nil {
			return fmt.Errorf("failed to query ethdev info: %v", err)
		}
		// set link status only for PF interfaces
		// if interface name doesn't contain "representor" it is PF interface
		if !strings.Contains(ethdevInfo.Value.Name, "representor") {
			var ethdevLinkStatus EthdevLinkStatus
			err = queryTelemetry(conn, log, fmt.Sprintf("/ethdev/link_status,%d", id), &ethdevLinkStatus)
			if err != nil {
				return fmt.Errorf("failed to query ethdev link status: %v", err)
			}
			var linkStatus float64
			if strings.ToLower(ethdevLinkStatus.Value.Status) == "up" {
				linkStatus = float64(1)
			} else if strings.ToLower(ethdevLinkStatus.Value.Status) == "down" {
				linkStatus = float64(0)
			} else {
				// if there is problem getting the link status skip this update
				continue
			}
			DpdkEthdevLinkStatus.With(prometheus.Labels{"name": ethdevInfo.Value.Name}).Set(linkStatus)
		}

		var ethdevXstats EthdevXstats
		err = queryTelemetry(conn, log, fmt.Sprintf("/ethdev/xstats,%d", id), &ethdevXstats)
		if err != nil {
			return fmt.Errorf("failed to query ethdev xstats: %v", err)
		}

		for statName, statValueFloat := range ethdevXstats.Value {
			if strings.Contains(statName, "bytes") {
				DpdkEthdevBytes.With(prometheus.Labels{"name": ethdevInfo.Value.Name, "stat": statName}).Set(statValueFloat)
			} else if strings.Contains(statName, "packets") {
				DpdkEthdevPackets.With(prometheus.Labels{"name": ethdevInfo.Value.Name, "stat": statName}).Set(statValueFloat)
			} else if strings.Contains(statName, "errors") {
				DpdkEthdevErrors.With(prometheus.Labels{"name": ethdevInfo.Value.Name, "stat": statName}).Set(statValueFloat)
			} else {
				DpdkEthdevMisc.With(prometheus.Labels{"name": ethdevInfo.Value.Name, "stat": statName}).Set(statValueFloat)
			}
		}
	}

	var dpserviceNatPortCount DpServiceNatPortCount
	err = queryTelemetry(conn, log, "/dp_service/nat/used_port_count", &dpserviceNatPortCount)
	if err != nil {
		return fmt.Errorf("failed to query used nat port count: %v", err)
	}
	for ifaceName, portCount := range dpserviceNatPortCount.Value {
		DpserviceUsedNatPortsCount.With(prometheus.Labels{"interface_id": ifaceName}).Set(float64(portCount))
	}

	var dpserviceVirtsvcPortCount DpServiceVirtsvcPortCount
	err = queryTelemetry(conn, log, "/dp_service/virtsvc/used_port_count", &dpserviceVirtsvcPortCount)
	if err != nil {
		return fmt.Errorf("failed to query used virtsvc port count: %v", err)
	}
	for virtsvc, portCount := range dpserviceVirtsvcPortCount.Value {
		DpserviceVirtsvcUsedPortsCount.With(prometheus.Labels{"address": virtsvc}).Set(float64(portCount))
	}

	var dpserviceFirewallRuleCount DpServiceFirewallRuleCount
	err = queryTelemetry(conn, log, "/dp_service/firewall/rule_count", &dpserviceFirewallRuleCount)
	if err != nil {
		return fmt.Errorf("failed to query firewall rule count: %v", err)
	}
	for ifaceName, fwRuleCount := range dpserviceFirewallRuleCount.Value {
		DpserviceFwRulesCount.With(prometheus.Labels{"interface_id": ifaceName}).Set(float64(fwRuleCount))
	}

	var dpserviceCallCount DpServiceGraphCallCount
	err = queryTelemetry(conn, log, "/dp_service/graph/call_count", &dpserviceCallCount)
	if err != nil {
		return fmt.Errorf("failed to query call count: %v", err)
	}
	for graphNodeName, callCount := range dpserviceCallCount.GraphCallCnt.Node_0_to_255 {
		DpserviceCallCount.With(prometheus.Labels{"node": hostname, "graph_node": graphNodeName}).Set(callCount)
	}

	var dpServiceHashTableSaturation DpServiceHashTableSaturation
	err = queryTelemetry(conn, log, "/dp_service/table/saturation", &dpServiceHashTableSaturation)
	if err != nil {
		return fmt.Errorf("failed to query table saturation: %v", err)
	}
	for table, saturation := range dpServiceHashTableSaturation.Value {
		DpserviceHashTableSaturation.With(prometheus.Labels{"table": table, "stat": "capacity"}).Set(saturation.Capacity)
		DpserviceHashTableSaturation.With(prometheus.Labels{"table": table, "stat": "entries"}).Set(saturation.Entries)
	}
	return nil
}
