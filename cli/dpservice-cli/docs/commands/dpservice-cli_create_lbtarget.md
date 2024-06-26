## dpservice-cli create lbtarget

Create a loadbalancer target

```
dpservice-cli create lbtarget <target-ip> <--lb-id> [flags]
```

### Examples

```
dpservice-cli create lbtarget --target-ip=ff80::5 --lb-id=2
```

### Options

```
  -h, --help           help for lbtarget
      --lb-id string   ID of the loadbalancer to add the target for.
      --target-ip ip   Loadbalancer Target IP. (default invalid IP)
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
