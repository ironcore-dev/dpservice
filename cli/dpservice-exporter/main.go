// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/ironcore-dev/dpservice/cli/dpservice-exporter/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

const (
	maxRetries = 5
	sleepTime  = 10 * time.Second
)

func main() {
	var conn net.Conn
	var err error
	var host string
	var hostnameFlag string
	var pollIntervalFlag int
	var exporterPort uint64
	var exporterAddr netip.AddrPort

	log := logrus.New()
	log.Formatter = new(logrus.JSONFormatter)

	r := prometheus.NewRegistry()
	r.MustRegister(metrics.InterfaceStat)
	r.MustRegister(metrics.CallCount)
	r.MustRegister(metrics.HeapInfo)

	http.Handle("/metrics", promhttp.HandlerFor(r, promhttp.HandlerOpts{}))

	conn = connectToDpdkTelemetry(log)
	defer conn.Close()

	flag.StringVar(&hostnameFlag, "hostname", "", "Hostname to use")
	flag.IntVar(&pollIntervalFlag, "poll-interval", 20, "Polling interval in seconds")
	flag.Uint64Var(&exporterPort, "port", 9064, "Port on which exporter will be running.")
	flag.Parse()

	if exporterPort < 1024 || exporterPort > 65535 {
		log.Fatal("port must be in range 1024 - 65535")
	}
	exporterAddr = netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(exporterPort))

	host, err = getHostname(hostnameFlag)
	if err != nil {
		log.Fatal("could not get hostname")
	}
	log.Infof("Hostname: %s", host)

	go func() {
		for {
			if !testDpdkConnection(conn, log) {
				log.Infof("Reconnecting to %s", metrics.SocketPath)
				conn = connectToDpdkTelemetry(log)
				log.Infof("Reconnected to %s", metrics.SocketPath)
			}
			metrics.Update(conn, host, log)
			time.Sleep(time.Duration(pollIntervalFlag) * time.Second)
		}
	}()

	log.Infof("Server starting on :%v...", exporterPort)

	err = http.ListenAndServe(exporterAddr.String(), nil)
	if err != nil {
		log.Fatalf("ListenAndServe failed: %d", err)
	}
}

// Tests if DPDK telemetry connection is working by writing to the connection
func testDpdkConnection(conn net.Conn, log *logrus.Logger) bool {
	_, err := conn.Write([]byte("/"))
	if err != nil {
		return false
	}
	flushErr := flushSocket(conn)
	if flushErr != nil {
		log.Fatalf("Failed to read response from %s: %v", metrics.SocketPath, err)
	}
	return true
}

// Connects to the DPDK telemetry
func connectToDpdkTelemetry(log *logrus.Logger) net.Conn {
	for i := 0; i < maxRetries; i++ {
		conn, err := net.Dial("unixpacket", metrics.SocketPath)
		if err == nil {
			err = flushSocket(conn)
			if err != nil {
				log.Fatalf("Failed to read response from %s: %v", metrics.SocketPath, err)
			}
			return conn
		}
		log.Warningf("Failed to connect to %s: %v. Retry %d of %d", metrics.SocketPath, err, i+1, maxRetries)
		if i < maxRetries-1 {
			time.Sleep(sleepTime)
		}
		if i == maxRetries-1 {
			log.Fatal("Exiting. Maximum connection retries reached")
		}
	}
	return nil
}

// Flushes the connection socket
func flushSocket(conn net.Conn) error {
	respBytes := make([]byte, 1024)

	_, err := conn.Read(respBytes)
	return err
}

// Gets the hostname from flag, env variable or OS hostname
func getHostname(hostnameFlag string) (string, error) {
	if hostnameFlag == "" {
		// Try to get hostname from environment variable
		envHostName := os.Getenv("NODE_NAME")
		if envHostName != "" {
			return envHostName, nil
		} else {
			// If environment variable not set, get hostname from os.Hostname
			hostname, err := os.Hostname()
			if err != nil {
				return "unknown", err
			} else {
				return hostname, nil
			}
		}
	} else {
		return hostnameFlag, nil
	}
}
