# Prerequisite: running dpservice

Before using dpservice-cli client, you need to have dpservice instance running.

Please refer to this guide [dpservice](https://github.com/ironcore-dev/dpservice/blob/osc/grpc_docs/docs/development/building.md) on how to build dpservice from source.

You can then run python script **/test/dp_service.py** that will start the dpservice with preloaded config.
```bash
sudo ./test/dp_service.py
```
If there is error about number of hugepages run this as root:
```bash
echo 2048 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages 
```


# Running dpservice-cli
When you are running dpservice on the same VM you don't need to specify the address and defaults are used (localhost:1337).  
If dpservice is running on different machine or you changed the default settings, use **--address \<string\>** flag:
```bash
./bin/dpservice-cli --address <IP:port> [command] [flags]
```
To change the output format of commands you can use **-o, --output** flag with one of **json | yaml | table | name**

  -  **json**   - shows output in json (you can use **--pretty** flag to show formatted json)
  -  **yaml**   - shows output in yaml
  -  **table**  - shows output in predefined table format (you can use **-w, --wide** for more information)
  -  **name**   - shows only short output with type/name

Add and Delete commands also support file input with **-f, --filename** flag:
```bash
./bin/dpservice-cli [add|delete] -f /<path>/<filename>.[json|yaml]
```
Filename, directory, or URL can be used.
One file can contain multiple objects of any kind.

# Command-line guidance

Each command or subcommand has help that can be viewed with -h or --help flag.
```shell
dpservice-cli --help
```
```bash
Usage:
  dpservice-cli [flags]
  dpservice-cli [command]

Available Commands:
  add         Creates one of [interface prefix route virtualip loadbalancer lbprefix lbtarget nat neighbornat firewallrule]
  completion  Generate completion script
  delete      Deletes one of [interface prefix route virtualip loadbalancer lbprefix lbtarget nat neighbornat firewallrule]
  get         Gets one of [interface virtualip loadbalancer lbtarget nat natinfo firewallrule]
  help        Help about any command
  init        Initial set up of the DPDK app
  initialized Indicates if the DPDK app has been initialized already
  list        Lists one of [firewallrules interfaces prefixes lbprefixes routes]

Flags:
      --address string             dpservice address. (default "localhost:1337")
      --connect-timeout duration   Timeout to connect to the dpservice. (default 4s)
  -h, --help                       help for dpservice-cli
  -o, --output string              Output format. [json|yaml|table|name]
      --pretty                     Whether to render pretty output.
  -w, --wide                       Whether to render more info in table output.

Use "dpservice-cli [command] --help" for more information about a command.
```
---
Add and Delete commands also support file input with **-f, --filename** flag:
```bash
dpservice-cli [add|delete] -f /<path>/<filename>.[json|yaml]
```
Filename, directory, or URL can be used.
One file can contain multiple objects of any kind, example file:
```bash
{"kind":"VirtualIP","metadata":{"interfaceID":"vm1"},"spec":{"ip":"20.20.20.20"}}
{"kind":"VirtualIP","metadata":{"interfaceID":"vm2"},"spec":{"ip":"20.20.20.21"}}
{"kind":"Prefix","metadata":{"interfaceID":"vm3"},"spec":{"prefix":"20.20.20.0/24"}}
{"kind":"LoadBalancer","metadata":{"id":"4"},"spec":{"vni":100,"lbVipIP":"10.20.30.40","lbports":[{"protocol":6,"port":443},{"protocol":17,"port":53}]}}
{"kind":"LoadBalancerPrefix","metadata":{"interfaceID":"vm1"},"spec":{"prefix":"10.10.10.0/24"}}
```

**Note**
All available commands can be found [here](/docs/commands/README.md).
