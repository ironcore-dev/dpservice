#!/usr/bin/env bash
#
# Remove everything the lab created. Deleting a namespace destroys every
# interface, state, policy and nftables table inside it, so this is complete.

set -uo pipefail
cd "$(dirname "$0")"
. ./00-common.sh

need_root

say "Removing namespaces"
for n in a b c d; do
  ns=$(node_ns "$n")
  if ip netns list 2>/dev/null | grep -qw "$ns"; then
    run ip netns del "$ns"
  else
    note "$ns not present"
  fi
done
if ip netns list 2>/dev/null | grep -qw mesh-sw; then
  run ip netns del mesh-sw
else
  note "mesh-sw not present"
fi

say "Removing any stranded veth"
for l in veth-a veth-b veth-c veth-d br-a br-b br-c br-d; do
  ip link del "$l" 2>/dev/null && note "deleted $l" || true
done

ok "clean"
note "nothing on the host was modified outside these namespaces"
