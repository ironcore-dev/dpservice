#!/usr/bin/env bash
#
# Dump everything relevant. Run any time.
#   ./show.sh            every lab namespace that exists
#   ./show.sh node-a     just one

set -uo pipefail
cd "$(dirname "$0")"
. ./00-common.sh

if [ $# -gt 0 ]; then
  TARGETS=$*
else
  TARGETS=""
  for n in a b c d; do
    ns=$(node_ns "$n")
    ip netns list 2>/dev/null | grep -qw "$ns" && TARGETS="$TARGETS $ns"
  done
  [ -n "$TARGETS" ] || die "no lab namespaces - run ./09-vni-pair.sh or ./10-vni-mesh.sh"
fi

for ns in $TARGETS; do
  printf '\n%s================ %s ================%s\n' "$C_B" "$ns" "$C_0"

  say "links"
  ip -n "$ns" -br link show 2>/dev/null

  say "addresses"
  ip -n "$ns" -br addr show 2>/dev/null

  say "routes"
  ip -n "$ns" -6 route show 2>/dev/null | grep -v '^fe80\|^ff00' || true

  say "xfrm states"
  ip -n "$ns" xfrm state 2>/dev/null

  say "xfrm policies"
  ip -n "$ns" xfrm policy 2>/dev/null

  say "mark rules"
  ip netns exec "$ns" nft list ruleset 2>/dev/null | grep -v '^$' \
    || ip netns exec "$ns" ip6tables -t mangle -L PREROUTING -nv 2>/dev/null \
    || note "none"

  say "non-zero error counters"
  xstat_nonzero "$ns"
done
