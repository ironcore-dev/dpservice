[Cobra](https://github.com/spf13/cobra) framework is used for generating and handling commands in this project.

# Generate current command-line tree
To generate current command tree add this at the start of main.go:
```
	err := doc.GenMarkdownTree(cmd.Command(), "/tmp/")
	if err != nil {
		log.Fatal(err)
	}
```
run the program once and then remove this code.
This will generate a whole series of files, one for each command in the tree, in the directory specified (in this case "/tmp/").

**Note** Cobra command Markdown [docs](https://github.com/spf13/cobra/blob/main/doc/md_docs.md)


# Steps to add a new subcommand
Basic steps when implementing new type (similar to Interface, Route, LoadBalancer, ...):
- Create new type in [/dpdk/api/types.go](/dpdk/api/types.go):
    - create structs and methods
	- at the bottom add new \<type\>Kind variable
- Create new [create|get|list|delete]\<type\>.go file in /cmd/ folder and implement the logic
- Add new command function to subcommands of matching parent command in /cmd/[create|get|list|delete].go
- If needed add aliases for \<type\> at the bottom of [/cmd/common.go](/cmd/common.go)
- Add new function to [/dpdk/api/client.go](/dpdk/api/client.go):
    - add function to Client interface
    - implement the function
- Add new \<type\> to DefaultScheme in [/dpdk/api/register.go](/dpdk/api/register.go)
- Add new \<type\>Key structs and methods in [/dpdk/client/dynamic/dynamic.go](/dpdk/client/dynamic/dynamic.go) and add new \<type\> to switch in Create and Delete methods
- If needed create new conversion function(s) between dpdk struct and local struct in [/dpdk/api/conversion.go](/dpdk/api/conversion.go)
- Add new function to show \<type\> as table in [/renderer/renderer.go](/renderer/renderer.go)
    - add new \<type\> to ConvertToTable method
    - implement function to show new \<type\>
