// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	dpdkproto "github.com/ironcore-dev/dpservice-go/proto"
	//+kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var (
	ctxCancel       context.CancelFunc
	ctxGrpc         context.Context
	dpserviceAddr   string = "127.0.0.1:1337"
	dpdkProtoClient dpdkproto.DPDKironcoreClient
	dpdkClient      Client
)

// This assumes running dp-service on the same localhost of this test suite
// /test/dp_service.py --no-init

func TestGrpcFuncs(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {

	//+kubebuilder:scaffold:scheme

	// setup net-dpservice client
	ctxGrpc, ctxCancel = context.WithTimeout(context.Background(), 100*time.Millisecond)

	conn, err := grpc.DialContext(ctxGrpc, dpserviceAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	Expect(err).NotTo(HaveOccurred())

	dpdkProtoClient = dpdkproto.NewDPDKironcoreClient(conn)
	dpdkClient = NewClient(dpdkProtoClient)

	_, err = dpdkClient.Initialize(context.TODO())
	Expect(err).NotTo(HaveOccurred())
})

var _ = AfterSuite(func() {

})
