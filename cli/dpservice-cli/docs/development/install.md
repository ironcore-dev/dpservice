# Compile and install

Go version 1.18 or newer is needed. \"make\" tool is also needed to utilize the Makefile.  
To run the dpservice-cli client build the binary first and then use it with commands and flags:
```bash
make build
./bin/dpservice-cli -h
```

This will build the binary at `bin/dpservice-cli`.
To install it on a system where `GOBIN` is part of the `PATH`,
run

```shell
make install
```

# Autocompletion

To generate autocompletion use:

```shell
dpservice-cli completion [bash|zsh|fish|powershell]
```

Or use -h to get more info and examples for specific shell:

```shell
dpservice-cli completion -h
```

# Dependency
This client uses golang bindings from repo [dpservice-go](https://github.com/ironcore-dev/dpservice-go).

Definition go files in [proto](https://github.com/ironcore-dev/dpservice-go/tree/main/proto) folder are auto-generated from [dpdk.proto](https://github.com/ironcore-dev/dpservice/blob/osc/main/proto/dpdk.proto) file in [dpservice](https://github.com/ironcore-dev/dpservice/) repo.

In case of upgrade of dpservice-go, it is needed to pull the latest version:
```
go get github.com/ironcore-dev/dpservice-go@[<version>|latest]
```
In order to pull from private repository set the **GOPRIVATE** variable:
```
export GOPRIVATE=github.com/ironcore-dev/*
```

More info about gRPC can be found [here](https://grpc.io/docs/what-is-grpc/introduction/).
