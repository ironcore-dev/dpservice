# dpservice-cli commands:

You can browse help for all commands starting in main command [here](/docs/commands/dpservice-cli.md)

# Available commands:

Most of the validation is done on server side (dpservice).
All parameters are validated based on their type (see below).
In some cases there is validation also on client side (dpservice-cli) user is then notified with proper usage.

## Initialization/check for initialized service, check version and generating auto-completion:
```
init
get init
get version
completion [bash|zsh|fish|powershell]
```

## Create/delete/list network interfaces:
```
create interface --id=<string> --ipv4=<netip.Addr> --ipv6=<netip.Addr> --vni=<uint32> --device=<string>
delete interface --id=<string>
get interface --id=<string>
list interfaces --sort-by=<string>
```

## Create/delete/list routes (ip route equivalents):
```
create route --prefix=<netip.Prefix> --next-hop-vni=<uint32> --next-hop-ip=<netip.Addr> --vni=<uint32>
delete route --prefix=<netip.Prefix> --vni=<uint32>
list routes --vni=<uint32> --sort-by=<string>
```

## Create/delete/list prefixes (to route other IP ranges to a given interface):
```
create prefix --prefix=<netip.Prefix> --interface-id=<string>
delete prefix --prefix=<netip.Prefix> --interface-id=<string>
list prefixes --interface-id=<string> --sort-by=<string>
```

## Create/delete/list loadbalancers:
```
create loadbalancer --id=<string> --vni=<uint32> --vip=<netip.Addr> --lbports=<string>
delete loadbalancer --id=<string>
get loadbalancer --id=<string>
```

## Create/delete/list loadbalancer backing IPs:
```
create lbtarget --target-ip=<netip.Addr> --lb-id=<string>
delete lbtarget --target-ip=<netip.Addr> --lb-id=<string>
list lbtargets --lb-id=<string> --sort-by=<string>
```

## Create/delete/list loadbalancer prefixes (call on loadbalancer targets so the public IP packets can reach them):
```
create lbprefix --prefix=<netip.Prefix> --interface-id=<string>
delete lbprefix --prefix=<netip.Prefix> --interface-id=<string>
list lbprefixes --interface-id=<string> --sort-by=<string>
```

## Create/delete/list a virtual IP for the interface (SNAT):
```
create virtualip --vip=<netip.Addr> --interface-id=<string>
delete virtualip --interface-id=<string>
get virtualip --interface-id=<string>
```

## Create/delete/list NAT IP (with port range) for the interface:
```
create nat --interface-id=<string> --nat-ip=<netip.Addr> --minport=<uint32> --maxport=<uint32>
delete nat --interface-id=<string>
get nat --interface-id=<string>
list nats --nat-ip=<netip.Addr> --sort-by=<string>
```

## Create/delete/list neighbors (dp-services) with the same NAT IP:
```
create neighbornat --nat-ip=<netip.Addr> --vni=<uint32> --minport=<uint32> --maxport=<uint32> --underlayroute=<netip.Addr>
delete neighbornat --nat-ip=<netip.Addr> --vni=<uint32> --minport=<uint32> --maxport=<uint32>
list nats --nat-ip=<netip.Addr> --nat-type=<string> --sort-by=<string>
```

## Create/delete/list firewall rules:
```
create fwrule --interface-id=<string> --action=<string> --direction=<string> --dst=<netip.Prefix> --priority=<uint32> --rule-id=<string> --src=<netip.Prefix> --protocol=<string> --src-port-min=<int32> --src-port-max=<int32> --dst-port-min=<int32> --dst-port-max=<int32> --icmp-type=<int32> --icmp-code=<int32>
delete firewallrule --rule-id=<string> --interface-id=<string>
get fwrule --rule-id=<string> --interface-id=<string>
list firewallrules --interface-id=<string> --sort-by=<string>
```

## Get/reset vni:
```
get vni --vni=<uint32> --vni-type=<uint8>
reset vni --vni=<uint32> --vni-type=<uint8>
```