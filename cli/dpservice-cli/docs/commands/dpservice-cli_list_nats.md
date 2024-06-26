## dpservice-cli list nats

List local/neighbor/both nats with selected IP

```
dpservice-cli list nats <--nat-ip> <--nat-type> [flags]
```

### Examples

```
dpservice-cli list nats --nat-ip=10.20.30.40 --info-type=local
```

### Options

```
  -h, --help              help for nats
      --nat-ip ip         NAT IP to get info for (default invalid IP)
      --nat-type string   NAT type: Any = 0/Local = 1/Neigh(bor) = 2 (default "0")
      --sort-by string    Column to sort by.
```

### Options inherited from parent commands

```
      --address string             dpservice address. (default "localhost:1337")
      --connect-timeout duration   Timeout to connect to the dpservice. (default 4s)
  -o, --output string              Output format. [json|yaml|table|name] (default "table")
      --pretty                     Whether to render pretty output.
  -w, --wide                       Whether to render more info in table output.
```

### SEE ALSO

* [dpservice-cli list](dpservice-cli_list.md)	 - Lists one of [firewallrules interfaces prefixes lbprefixes routes lbtargets nats loadbalancers]

###### Auto generated by spf13/cobra on 31-May-2024
