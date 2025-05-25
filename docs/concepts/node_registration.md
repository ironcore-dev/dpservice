# RTE Graph Nodes Registration
To eliminate error-prone boiler-plate for RTE graph node implementation, a set of macros has been created in `include/nodes/common_node.h`.

For the simplest usage while implementing nodes, whese macros have to be slightly complex metaprogramming however, thus the need for this document. 


## Overview
This macro system:
 - Automates the boilerplate for `struct rte_node_register`.
 - Enforces certain invariants (e.g., `DROP` is always 0, `MAX` is always last).
 - Supports optional “next nodes” via an [X-macro](https://en.wikipedia.org/wiki/X_macro)-like mechanism.
 - Automatically generates enums and string mappings for next node edges.
 - Ensures consistency and compile-time validation.

## Key Concepts
 - `UPPER_NODE_NAME`: Used for enum constants like `MYNODE_NEXT_DROP`.
 - `LOWER_NODE_NAME`: Used to generate symbols (`mynode_node_register`, etc.).
 - `EXTRA_NEXT_NODES(X)`: A macro expansion point that acts like an X-macro:
```c
#define NEXT_NODES(NEXT) \
	NEXT(MYNODE_NEXT_FOO, "foo") \
	NEXT(MYNODE_NEXT_BAR, "bar")
```
 - `DROP` is always index 0; `MAX` is auto-computed at the end.

## What Each Macro Does
### `_DP_NODE_REGISTER_GENERATE_ENUM(...)`
Generates enum entries:
```c
MYNODE_NEXT_FOO,
MYNODE_NEXT_BAR,
...
```

### `_DP_NODE_REGISTER_GENERATE_NEXT_NODES(...)`
Generates array entries mapping enum index to string:
```c
[MYNODE_NEXT_FOO] = "foo",
[MYNODE_NEXT_BAR] = "bar",
...
```

### `_DP_NODE_REGISTER(...)`
This is the heart of the system:
 1. Declares a process function `mynode_node_process` for the node.
 2. Declares an enum of next node targets:
```c
enum mynode_next_node {
	MYNODE_NEXT_DROP,
	MYNODE_NEXT_FOO,
	MYNODE_NEXT_BAR,
	MYNODE_NEXT_MAX
};
```
 3. Defines a struct `rte_node_register` with automatically filled-in:
  - name
  - flags
  - init/process functions
  - computed edge count (i.e. `MYNODE_NEXT_MAX`)
  - `next_nodes` array with `DROP` always being the first one
 4. Then calls `RTE_NODE_REGISTER(...)` on that struct.

> The resulting `struct rte_node_register` is then accessible via `DP_NODE_GET_SELF(mynode)`.

#### Variants
 - `DP_NODE_REGISTER`: With custom `init()` function declaration that needs to be implemented.
 - `DP_NODE_REGISTER_NOINIT`: No `init()` function declared, thus no need to implement one.
 - `DP_NODE_REGISTER_SOURCE`: With `RTE_NODE_SOURCE_F` flag.

All of these wrap `_DP_NODE_REGISTER_INIT` or `_DP_NODE_REGISTER`.

### `DP_NODE_DEFAULT_NEXT_ONLY(NEXT)`
This just expands to nothing. It’s a placeholder macro to indicate there are no extra user-defined next nodes. There is still the `DROP` next node and others can be connected dynamically later (e.g. Tx nodes).


## Example Usage
```c
#define NEXT_NODES(NEXT) \
	NEXT(MYNODE_NEXT_FWD, "fwd") \
	NEXT(MYNODE_NEXT_LOG, "log")

DP_NODE_REGISTER(MYNODE, mynode, NEXT_NODES);
```
Expands into:
 - A declaration of `mynode_node_init()` function that needs to be implemented otherwise the compiler will throw an error.
 - A declaration of `mynode_node_process()` function that needs to be implemented otherwise the compiler will throw an error.
 - An enum with constants to be used by code in `mynode_node_process()`:
```c
enum mynode_next_node {
	MYNODE_NEXT_DROP,
	MYNODE_NEXT_FWD,
	MYNODE_NEXT_LOG,
	MYNODE_NEXT_MAX
};
```
 - A static `mynode_node_register` struct.
 - An `RTE_NODE_REGISTER(...)` invocation.

### Minimal working example
```c
#include <rte_graph.h>
#include <rte_node.h>
#include "dp_error.h"
#include "nodes/common_node.h"

// Registration of a node named "mynode" under UPPER name "MYNODE"
DP_NODE_REGISTER(MYNODE, mynode, DP_NODE_DEFAULT_NEXT_ONLY);

// Implement the init function (required by DP_NODE_REGISTER)
static int mynode_node_init(const struct rte_graph *graph, struct rte_node *node) {
	// Custom per-node initialization. If not needed, use DP_NODE_REGISTER_NOINIT instead.
	(void)graph;
	(void)node;
	return DP_OK;
}

// Implement the process function (required)
static uint16_t mynode_node_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	// For this minimal example, we just send everything to DROP
	dp_forward_graph_packets(graph, node, objs, nb_objs, MYNODE_NEXT_DROP);
	return nb_objs;
}
```
Compiler then expands `DP_NODE_REGISTER(...)` to:
```c
enum mynode_next_node {
	MYNODE_NEXT_DROP,
	MYNODE_NEXT_MAX
};

static struct rte_node_register mynode_node_register = {
	.name = "mynode",
	.flags = 0,
	.init = mynode_node_init,
	.process = mynode_node_process,
	.nb_edges = MYNODE_NEXT_MAX,
	.next_nodes = {
		[MYNODE_NEXT_DROP] = "drop",
	},
};

RTE_NODE_REGISTER(mynode_node_register);
```

