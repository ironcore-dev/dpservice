# Generate gRPC bindings

To manually regenerate the gRPC Go bindings run:

```shell
make clean generate
```

This will generate gRPC Go files from [protofile](/proto/dpdk.proto) into proto [folder](/go/dpservice-go/proto/)

## Usage examples

Here is an example of how to integrate dpservice-go bindings in your developed applications.

```go
package main

import (
    "context"
    dpdkproto "github.com/ironcore-dev/dpservice/go/dpservice-go/proto"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

func main() {
    ctx := context.Background()
    conn, err := grpc.DialContext(ctx, "127.0.0.1", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
    if err != nil {
    panic("aaaahh")
    }
    client := dpdkproto.NewDPDKironcoreClient(conn)
    ...
}
```

## Testing

Tests are created with use of Ginkgo and Gomega frameworks.
Test cases are running in parallel and can be filtered by label.
They are split to positive and negative: positive tests are expected to be successfull, negative tests are expected to return error.

To run the test of dpservice-go gRPC library, you need to have dpservice-bin running on the same host on port 1337 and dpservice needs to be uninitialized.
If dpservice is already initialized, tests will fail in BeforeSuite stage. When rerunning tests, dpservice needs to be restarted before each run.

To run all tests:

```shell
make test
```

To filter tests (one or more labels can be filtered):

```shell
make test labels=<string>,<string>,...
```
