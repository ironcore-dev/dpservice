#!/usr/bin/env bash
#
# 09-vni-mesh.sh - the per-VNI encryption mesh from the diagram.
#
#   VNI 42: full mesh A, B, C, D      (6 edges)
#   VNI 77: mesh A, C, D only          (3 edges)
#
# Every node has a unique underlay /64. SPI is EXACTLY the VNI, on every SA,
# in both directions. Inbound states that collide on (dst, spi, proto) are
# separated by a packet mark carrying the SENDER's node id, set from the outer
# source /64 in nftables PREROUTING. Verified by 07-marktest.sh.
#
# Per-SA keys are derived from a per-VNI master key. This is NOT optional:
# AES-GCM builds its nonce from salt||sequence, so two SAs sharing a key and
# starting at sequence 1 emit identical nonces - which under GCM leaks the XOR
# of plaintexts and enables tag forgery. Derivation gives every SA distinct
# key+salt material while keeping "one key per VNI" as the operational model.
#
# NOT included, deliberately:
#   - VRFs. Overlay prefixes here are distinct per VNI (fd2a:: vs fd4d::), so
#     there is no address overlap to separate. Real tenants reuse addresses;
#     add one VRF per VNI and put each ipsec-* interface in it. See README.
#   - flag af-unspec. Inner and outer are both IPv6 here, so it is unnecessary.
#     Add it back if you carry IPv4 inside.
#
# Self-contained. Tears down its own namespaces on entry.

set -uo pipefail
cd "$(dirname "$0")"
. ./00-common.sh

need_root

NODES="a b c d"
VNIS="42 77"
MEMBERS_42="a b c d"
MEMBERS_77="a c d"
SWNS=mesh-sw
FAILURES=0

fail() { printf '    %s[FAIL]%s %s\n' "$C_R" "$C_0" "$*"; FAILURES=$((FAILURES+1)); }
pass() { printf '    %s[PASS]%s %s\n' "$C_G" "$C_0" "$*"; }

members_of(){ case $1 in 42) echo "$MEMBERS_42";; 77) echo "$MEMBERS_77";; esac; }
is_member() { case " $(members_of "$1") " in *" $2 "*) return 0;; *) return 1;; esac; }


# ===========================================================================
say "Teardown"
for n in $NODES; do ip netns del "$(node_ns "$n")" 2>/dev/null; done
ip netns del "$SWNS" 2>/dev/null
for n in $NODES; do ip link del "veth-$n" 2>/dev/null; ip link del "br-$n" 2>/dev/null; done
sleep 0.3
ok "clean"

# ===========================================================================
say "Underlay: four nodes, one segment, a unique /64 each"

ip netns add "$SWNS"
ip netns exec "$SWNS" sysctl -qw net.ipv6.conf.all.accept_dad=0
ip -n "$SWNS" link add br0 type bridge forward_delay 0 stp_state 0
ip -n "$SWNS" link set br0 up
ip -n "$SWNS" link set lo up

for n in $NODES; do
  ns=$(node_ns "$n")
  ip netns add "$ns"
  ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.accept_dad=0
  ip netns exec "$ns" sysctl -qw net.ipv6.conf.default.accept_dad=0
  ip -n "$ns" link set lo up

  ip link add "veth-$n" type veth peer name "br-$n"
  ip link set "veth-$n" netns "$ns"
  ip link set "br-$n" netns "$SWNS"
  ip -n "$SWNS" link set "br-$n" master br0
  ip -n "$SWNS" link set "br-$n" up
  ip -n "$ns" addr add "$(node_outer "$n")/64" dev "veth-$n" nodad
  ip -n "$ns" link set "veth-$n" up
done

# each node's /64 differs, so peers need explicit on-link routes
for n in $NODES; do
  for p in $NODES; do
    [ "$p" = "$n" ] && continue
    ip -n "$(node_ns "$n")" route add "$(node_opfx "$p")" dev "veth-$n"
  done
done

for n in $NODES; do
  for p in $NODES; do
    [ "$p" = "$n" ] && continue
    ip netns exec "$(node_ns "$n")" ping -6 -c1 -W2 "$(node_outer "$p")" >/dev/null 2>&1 \
      || die "underlay: $n cannot reach $p"
  done
done
ok "underlay full mesh reachable"

# ===========================================================================
say "Mark rules: outer source /64 -> sender node id"
note "N-1 rules per node, INDEPENDENT of how many VNIs exist - the SPI already"
note "separates VNIs, so the mark only has to identify the sender"

for n in $NODES; do
  rules=""
  for p in $NODES; do
    [ "$p" = "$n" ] && continue
    rules="$rules
    meta l4proto esp ip6 saddr $(node_opfx "$p") counter meta mark set $(node_id "$p")"
  done
  ip netns exec "$(node_ns "$n")" nft -f - <<EOF 2>/dev/null
table inet vnimesh {
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;$rules
  }
}
EOF
  if [ $? -eq 0 ]; then
    ok "node $n: $(( $(echo "$NODES" | wc -w) - 1 )) mark rules"
  else
    note "node $n: nftables unavailable, falling back to ip6tables"
    for p in $NODES; do
      [ "$p" = "$n" ] && continue
      ip netns exec "$(node_ns "$n")" ip6tables -t mangle -A PREROUTING \
        -s "$(node_opfx "$p")" -p esp -j MARK --set-mark "$(node_id "$p")" 2>/dev/null \
        || fail "node $n: could not install mark rule for $p"
    done
  fi
done

pause
# ===========================================================================
say "Per-VNI interfaces, SAs and policies"

for vni in $VNIS; do
  ifid=$(vni_ifid "$vni")
  mem=$(members_of "$vni")
  note ""
  note "VNI $vni  (spi $vni, if_id $ifid)  members: $mem"

  for n in $mem; do
    ns=$(node_ns "$n")
    ip -n "$ns" link add "ipsec-$vni" type xfrm dev "veth-$n" if_id "$ifid"
    ip -n "$ns" link set "ipsec-$vni" up
    ip -n "$ns" link set "ipsec-$vni" mtu 1400
    ip -n "$ns" addr add "$(ovl_addr "$vni" "$n")/128" dev "ipsec-$vni" nodad
  done

  for n in $mem; do
    ns=$(node_ns "$n")
    for p in $mem; do
      [ "$p" = "$n" ] && continue

      # OUTBOUND n -> p. No mark: the destination address already
      # distinguishes peers in the state_bydst lookup.
      ip -n "$ns" xfrm state add \
          src "$(node_outer "$n")" dst "$(node_outer "$p")" \
          proto esp spi "$vni" reqid "$vni" mode tunnel if_id "$ifid" \
          replay-window 64 \
          aead 'rfc4106(gcm(aes))' "$(sa_key "$vni" "$n" "$p")" 128 \
          sel src "$(ovl_net "$vni" "$n")" dst "$(ovl_net "$vni" "$p")" \
        || fail "out state $n->$p vni $vni"

      # INBOUND p -> n. Mark carries the SENDER id, which is the only thing
      # separating this from the other inbound states with the same spi.
      ip -n "$ns" xfrm state add \
          src "$(node_outer "$p")" dst "$(node_outer "$n")" \
          proto esp spi "$vni" reqid "$vni" mode tunnel if_id "$ifid" \
          mark "$(node_id "$p")" mask 0xff output-mark 0x0 mask 0xff \
          replay-window 64 \
          aead 'rfc4106(gcm(aes))' "$(sa_key "$vni" "$p" "$n")" 128 \
          sel src "$(ovl_net "$vni" "$p")" dst "$(ovl_net "$vni" "$n")" \
        || fail "in state $p->$n vni $vni"

      # policies: inner prefix picks the peer, template supplies the outer
      ip -n "$ns" xfrm policy add dir out if_id "$ifid" \
          src "$(ovl_net "$vni" "$n")" dst "$(ovl_net "$vni" "$p")" \
          tmpl src "$(node_outer "$n")" dst "$(node_outer "$p")" \
               proto esp reqid "$vni" mode tunnel \
        || fail "out policy $n->$p vni $vni"
      ip -n "$ns" xfrm policy add dir in if_id "$ifid" \
          src "$(ovl_net "$vni" "$p")" dst "$(ovl_net "$vni" "$n")" \
          tmpl src "$(node_outer "$p")" dst "$(node_outer "$n")" \
               proto esp reqid "$vni" mode tunnel \
        || fail "in policy $p->$n vni $vni"

      ip -n "$ns" route add "$(ovl_net "$vni" "$p")" dev "ipsec-$vni" \
          src "$(ovl_addr "$vni" "$n")"
    done
    ok "node $n vni $vni configured"
  done
done

pause
# ===========================================================================
say "Object count"
printf '    %-6s %-8s %-8s %-8s %s\n' node states policies ifaces markrules
for n in $NODES; do
  ns=$(node_ns "$n")
  s=$(ip -n "$ns" xfrm state | grep -c '^src' || true)
  p=$(ip -n "$ns" xfrm policy | grep -c '^src' || true)
  i=$(ip -n "$ns" link show type xfrm 2>/dev/null | grep -c 'ipsec-' || true)
  m=$(ip netns exec "$ns" nft list chain inet vnimesh prerouting 2>/dev/null | grep -c 'mark set' || true)
  printf '    %-6s %-8s %-8s %-8s %s\n' "$n" "$s" "$p" "$i" "$m"
done
note ""
note "node b has fewer objects because it is not in VNI 77 - matches the diagram"

pause
# ===========================================================================
say "Verification 1: VNI 42 full mesh"
for n in $MEMBERS_42; do
  for p in $MEMBERS_42; do
    [ "$p" = "$n" ] && continue
    if ip netns exec "$(node_ns "$n")" ping -6 -c2 -i 0.2 -W2 "$(ovl_addr 42 "$p")" >/dev/null 2>&1
    then pass "42: $n -> $p"; else fail "42: $n -> $p"; fi
  done
done

say "Verification 2: VNI 77 mesh (A, C, D only)"
for n in $MEMBERS_77; do
  for p in $MEMBERS_77; do
    [ "$p" = "$n" ] && continue
    if ip netns exec "$(node_ns "$n")" ping -6 -c2 -i 0.2 -W2 "$(ovl_addr 77 "$p")" >/dev/null 2>&1
    then pass "77: $n -> $p"; else fail "77: $n -> $p"; fi
  done
done

say "Verification 3: node B is absent from VNI 77"
if ip -n "$(node_ns b)" link show ipsec-77 >/dev/null 2>&1; then
  fail "b unexpectedly has an ipsec-77 interface"
else
  pass "b has no ipsec-77 interface"
fi
if ip netns exec "$(node_ns a)" ping -6 -c1 -W2 "$(ovl_addr 77 b)" >/dev/null 2>&1; then
  fail "a reached a VNI-77 address on b - should be impossible"
else
  pass "a cannot reach b on VNI 77"
fi

pause
# ===========================================================================
say "Verification 4: tenant isolation - VNI 42 traffic never touches ipsec-77"

rx77() { ip -n "$(node_ns a)" -s link show ipsec-77 | awk '/RX:/{getline; print $2; exit}'; }
B77=$(rx77)
note "node a ipsec-77 RX bytes before: $B77"
note "sending 20 pings on VNI 42 between a and c..."
ip netns exec "$(node_ns a)" ping -6 -c20 -i 0.1 -W1 "$(ovl_addr 42 c)" >/dev/null 2>&1
A77=$(rx77)
note "node a ipsec-77 RX bytes after:  $A77"
if [ "${B77:-0}" -eq "${A77:-1}" ]; then
  pass "not one byte of VNI-42 traffic surfaced on ipsec-77"
else
  fail "ipsec-77 counters moved during VNI-42 traffic ($((A77 - B77)) bytes)"
fi

say "Verification 5: anti-replay is genuinely active"
note "window > 32 uses the BMP implementation, so the legacy 'replay-window'"
note "field reads 0 and the real window lives in the context block below"
RW=$(ip -n "$(node_ns a)" xfrm state | grep -c 'replay_window 64' || true)
EXPECTED=$(ip -n "$(node_ns a)" xfrm state | grep -c '^src' || true)
if [ "$RW" -eq "$EXPECTED" ] && [ "$RW" -gt 0 ]; then
  pass "all $RW states on node a carry a 64-packet replay window"
else
  fail "expected $EXPECTED states with replay_window 64, found $RW"
fi
ip -n "$(node_ns a)" xfrm state | grep -A2 'anti-replay esn context' | head -4 | sed 's/^/    /'

say "Verification 6: per-SA keys really are distinct"
NKEYS=$(ip -n "$(node_ns a)" xfrm state | grep -o 'rfc4106(gcm(aes)) 0x[0-9a-f]*' | sort -u | wc -l)
NSTATES=$(ip -n "$(node_ns a)" xfrm state | grep -c '^src' || true)
if [ "$NKEYS" -eq "$NSTATES" ]; then
  pass "$NKEYS distinct keys across $NSTATES states - no GCM nonce reuse"
else
  fail "$NKEYS distinct keys for $NSTATES states - SAs are sharing key material"
fi

pause
# ===========================================================================
say "Verification 7: a wrong key is rejected, not leaked"
note "breaking node b's inbound key for traffic from a, on VNI 42"

BEFORE=$(xstat "$(node_ns b)" XfrmInStateProtoError); BEFORE=${BEFORE:-0}
ip -n "$(node_ns b)" xfrm state delete src "$(node_outer a)" dst "$(node_outer b)" \
    proto esp spi 42 mark "$(node_id a)" mask 0xff 2>/dev/null
ip -n "$(node_ns b)" xfrm state add \
    src "$(node_outer a)" dst "$(node_outer b)" \
    proto esp spi 42 reqid 42 mode tunnel if_id "$(vni_ifid 42)" \
    mark "$(node_id a)" mask 0xff output-mark 0x0 mask 0xff \
    replay-window 64 \
    aead 'rfc4106(gcm(aes))' 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef 128 \
    sel src "$(ovl_net 42 a)" dst "$(ovl_net 42 b)" 2>/dev/null

ip netns exec "$(node_ns a)" ping -6 -c3 -i 0.2 -W1 "$(ovl_addr 42 b)" >/dev/null 2>&1
AFTER=$(xstat "$(node_ns b)" XfrmInStateProtoError); AFTER=${AFTER:-0}
if [ "$AFTER" -gt "$BEFORE" ]; then
  pass "wrong key -> XfrmInStateProtoError +$((AFTER - BEFORE)), traffic dropped"
else
  fail "wrong key did not raise XfrmInStateProtoError (was $BEFORE, now $AFTER)"
fi

note "restoring b's correct key..."
ip -n "$(node_ns b)" xfrm state delete src "$(node_outer a)" dst "$(node_outer b)" \
    proto esp spi 42 mark "$(node_id a)" mask 0xff 2>/dev/null
ip -n "$(node_ns b)" xfrm state add \
    src "$(node_outer a)" dst "$(node_outer b)" \
    proto esp spi 42 reqid 42 mode tunnel if_id "$(vni_ifid 42)" \
    mark "$(node_id a)" mask 0xff output-mark 0x0 mask 0xff \
    replay-window 64 \
    aead 'rfc4106(gcm(aes))' "$(sa_key 42 a b)" 128 \
    sel src "$(ovl_net 42 a)" dst "$(ovl_net 42 b)" 2>/dev/null
if ip netns exec "$(node_ns a)" ping -6 -c2 -W2 "$(ovl_addr 42 b)" >/dev/null 2>&1
then pass "restored"; else fail "restore failed"; fi

# ===========================================================================
echo
printf '%s================ VERDICT ================%s\n' "$C_B" "$C_0"
if [ "$FAILURES" -eq 0 ]; then
  printf '  %sALL CHECKS PASSED%s\n\n' "$C_G" "$C_0"
  echo "  SPI = VNI on every SA. Colliding inbound states separated by a"
  echo "  sender mark. Per-VNI interfaces, per-SA keys, 64-packet replay"
  echo "  windows, and tenant isolation holding under traffic."
else
  printf '  %s%s CHECK(S) FAILED%s\n' "$C_R" "$FAILURES" "$C_0"
fi
printf '%s========================================%s\n' "$C_B" "$C_0"
echo
note "inspect:   ip netns exec node-a ip xfrm state"
note "plaintext: ip netns exec node-a tcpdump -ni ipsec-42"
note "wire:      ip netns exec node-a tcpdump -ni veth-a esp"
note "teardown:  sudo ./99-cleanup.sh"
