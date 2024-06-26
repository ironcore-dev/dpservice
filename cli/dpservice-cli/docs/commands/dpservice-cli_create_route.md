## dpservice-cli create route

Create a route

```
dpservice-cli create route <--prefix> <--next-hop-vni> <--next-hop-ip> <--vni> [flags]
```

### Examples

```
dpservice-cli create route --prefix=10.100.3.0/24 --next-hop-vni=0 --next-hop-ip=fc00:2::64:0:1 --vni=100
```

### Options

```
  -h, --help                  help for route
      --next-hop-ip ip        Next hop IP for the route. (default invalid IP)
      --next-hop-vni uint32   Next hop VNI for the route.
      --prefix ipprefix       Prefix for the route. (default invalid Prefix)
      --vni uint32            Source VNI for the route.
```

### Options inherited from parent commands

```
      --address string             dpservice address. (default "localhost:1337")
      --connect-timeout duration   Timeout to connect to the dpservice. (default 4s)
  -o, --output string              Output format. [json|yaml|table|name] (default "name")
      --pretty                     Whether to render pretty output.
  -w, --wide                       Whether to render more info in table output.
```

### SEE ALSO

* [dpservice-cli create](dpservice-cli_create.md)	 - Creates one of [interface prefix route virtualip loadbalancer lbprefix lbtarget nat neighbornat firewallrule]

###### Auto generated by spf13/cobra on 31-May-2024
