## Generate bindings

To regenerate the golang bindings run

```shell
make clean generate
```

## Usage examples
Here is an example on how to integrate dpservice-go bindings in your developed applications.

```go
package main

import (
    "context"
    dpdkproto "github.com/ironcore-dev/dpservice-go/proto"
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
