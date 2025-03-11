// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/user"
	"reflect"
	"strconv"
	"time"

	"github.com/ironcore-dev/dpservice/cli/dpservice-exporter/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

const (
	retryInterval = 5 * time.Second
)

var (
	version          = "unknown"
	grpcPort         uint64
	host             string
	pollIntervalFlag int
)

func main() {
	var err error
	var hostnameFlag, filePrefix string
	var exporterPort uint64
	var exporterAddr netip.AddrPort

	flag.StringVar(&hostnameFlag, "hostname", "", "Hostname to use (defaults to current hostname)")
	flag.StringVar(&filePrefix, "file-prefix", "rte", "File prefix of dpservice dpdk telemetry socket.")
	flag.IntVar(&pollIntervalFlag, "poll-interval", 20, "Polling interval in seconds")
	flag.Uint64Var(&exporterPort, "port", 9064, "Port on which exporter will be running.")
	flag.Uint64Var(&grpcPort, "grpc-port", 1337, "Port on which dpservice is running.")
	getVersion := flag.Bool("v", false, "Print version and exit")
	flag.Parse()

	if *getVersion {
		fmt.Printf("dpservice-exporter version %s\n", version)
		return
	}

	log := logrus.New()
	log.Formatter = new(logrus.JSONFormatter)

	if exporterPort < 1024 || exporterPort > 65535 {
		log.Fatal("port must be in range 1024 - 65535")
	}
	exporterAddr = netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(exporterPort))

	host, err = getHostname(hostnameFlag)
	if err != nil {
		log.Fatal("could not get hostname")
	}
	log.Infof("Hostname: %s", host)

	uid, err := getUID()
	if err != nil {
		log.Warningf("Could not get UID, assuming root: %v", err)
	}
	// Set DPDK telemetry socket path based on UID
	if uid == 0 {
		metrics.SocketPath = fmt.Sprintf("/var/run/dpdk/%s/dpdk_telemetry.v2", filePrefix)
	} else {
		metrics.SocketPath = fmt.Sprintf("/run/user/%d/dpdk/%s/dpdk_telemetry.v2", uid, filePrefix)
	}

	r := prometheus.NewRegistry()
	registerAllMetrics(r, log)

	http.Handle("/metrics", promhttp.HandlerFor(r, promhttp.HandlerOpts{}))

	exitChan := make(chan struct{})
	go periodicMetricsUpdate(log, exitChan)

	// Run server in goroutine
	log.Infof("Server starting on :%v...", exporterPort)
	server := &http.Server{Addr: exporterAddr.String()}
	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Errorf("ListenAndServe failed: %v", err)
		}
	}()

	<-exitChan
	// Create a context with a timeout to ensure the server shuts down gracefully
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Shutdown the server
	log.Info("Shutting down server...")
	if err := server.Shutdown(ctx); err != nil {
		log.Infof("HTTP server Shutdown error: %v\n", err)
	}
}

// Checks if dpservice GRPC TCP port on localhost is open
func testGrpcConnection(log *logrus.Logger) bool {
	dpserviceAddress := fmt.Sprintf("127.0.0.1:%d", grpcPort)
	tcpConn, err := net.DialTimeout("tcp", dpserviceAddress, 2*time.Second)
	if err != nil {
		log.Errorf("TCP port %d on localhost is not open: %v. Retry in %d seconds.", grpcPort, err, int(retryInterval.Seconds()))
		return false
	}
	defer tcpConn.Close()

	return true
}

// Connects to the DPDK telemetry
func connectToDpdkTelemetry(log *logrus.Logger) net.Conn {
	conn, err := net.Dial("unixpacket", metrics.SocketPath)
	if err != nil {
		return nil
	} else {
		err = flushSocket(conn)
		if err != nil {
			log.Errorf("Failed to read response from %s: %v", metrics.SocketPath, err)
			return nil
		}
		return conn
	}
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

// Gets UID from os
func getUID() (int, error) {
	user, err := user.Current()
	if err != nil {
		return 0, fmt.Errorf("could not get user: %v", err)
	}
	uid, err := strconv.Atoi(user.Uid)
	if err != nil {
		return 0, fmt.Errorf("could not get uid: %v", err)
	}
	return uid, nil
}

// Initializes connection and updates metric in pollIntervalFlag period
func periodicMetricsUpdate(log *logrus.Logger, exitChan chan struct{}) {
	log.Infof("Waiting for GRPC 127.0.0.1:%d", grpcPort)
	for !testGrpcConnection(log) {
		time.Sleep(retryInterval)
	}
	log.Infof("Connected to GRPC 127.0.0.1:%d", grpcPort)

	log.Infof("Trying to connect to dpdk telemetry socket: %s", metrics.SocketPath)
	conn := connectToDpdkTelemetry(log)
	if conn == nil {
		log.Error("Connection to dpdk telemetry failed; exiting...")
		exitChan <- struct{}{}
		return
	}
	defer conn.Close()
	log.Infof("Connected to dpdk telemetry socket: %s", metrics.SocketPath)

	log.Infof("Starting to update metrics in %d second intervals.", pollIntervalFlag)
	for {
		err := metrics.Update(conn, host, log)
		if err != nil {
			log.Errorf("Connection to dpdk telemetry failed: %v; exiting...", err)
			exitChan <- struct{}{}
			return
		}
		time.Sleep(time.Duration(pollIntervalFlag) * time.Second)
	}
}

func registerAllMetrics(r *prometheus.Registry, log *logrus.Logger) {
	metricsList := []prometheus.Collector{
		metrics.DpdkEthdevErrors,
		metrics.DpdkEthdevPackets,
		metrics.DpdkEthdevBytes,
		metrics.DpdkEthdevMisc,
		metrics.DpdkEthdevLinkStatus,
		metrics.DpdkHeapInfo,
		metrics.DpserviceUsedNatPortsCount,
		metrics.DpserviceFwRulesCount,
		metrics.DpserviceVirtsvcUsedPortsCount,
		metrics.DpserviceCallCount,
		metrics.DpserviceHashTableSaturation,
	}

	for _, metric := range metricsList {
		v := reflect.ValueOf(metric)
		if v.Kind() == reflect.Ptr && v.Elem().CanInterface() {
			r.MustRegister(v.Elem().Interface().(prometheus.Collector))
		} else {
			log.Errorf("Invalid metric type: %T", metric)
		}
	}
}
