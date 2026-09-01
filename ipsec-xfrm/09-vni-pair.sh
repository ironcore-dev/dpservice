#!/usr/bin/env bash
#
# 09-vni-pair.sh - the smallest complete version of the per-VNI design.
#
#   Node A  <--- one link, two encrypted tenants --->  Node C
#
#   VNI 42   spi 42   if_id 0x2a   ipsec-42   fd2a:a::1  <-->  fd2a:c::1
#   VNI 77   spi 77   if_id 0x4d   ipsec-77   fd4d:a::1  <-->  fd4d:c::1
#
# Four states and four policies per node. Every command is printed, nothing is
# hidden in a loop, and the whole configuration fits on one screen. Run
# 10-vni-mesh.sh afterwards for the four-node version.
#
# HONEST NOTE ON MARKS: with only two nodes there is no inbound collision -
# each node has exactly one inbound state per VNI, and the SPIs already differ
# between VNIs. The mark is a no-op here. It is included anyway because the
# configuration must be shape-identical to the N-node case, and this shows it
# costs nothing. 07-marktest.sh is what actually proves the collision handling.
#
# Self-contained. Tears down its own namespaces on entry.

set -uo pipefail
cd "$(dirname "$0")"
. ./00-common.sh

need_root

A_NS=$(node_ns a);  C_NS=$(node_ns c)
A_OUT=$(node_outer a); C_OUT=$(node_outer c)
A_PFX=$(node_opfx a);  C_PFX=$(node_opfx c)
A_ID=$(node_id a);     C_ID=$(node_id c)

FAILURES=0
fail() { printf '    %s[FAIL]%s %s\n' "$C_R" "$C_0" "$*"; FAILURES=$((FAILURES+1)); }
pass() { printf '    %s[PASS]%s %s\n' "$C_G" "$C_0" "$*"; }

# ===========================================================================
say "Teardown"
ip netns del "$A_NS" 2>/dev/null; ip netns del "$C_NS" 2>/dev/null
ip link del veth-a 2>/dev/null; ip link del veth-c 2>/dev/null
sleep 0.3
ok "clean"

# ===========================================================================
say "Underlay: a direct link, a unique /64 each"
note "no bridge needed for two nodes - veth-a and veth-c are the two ends"

for pair in "$A_NS" "$C_NS"; do
  run ip netns add "$pair"
  ip netns exec "$pair" sysctl -qw net.ipv6.conf.all.accept_dad=0
  ip netns exec "$pair" sysctl -qw net.ipv6.conf.default.accept_dad=0
  ip -n "$pair" link set lo up
done

run ip link add veth-a type veth peer name veth-c
run ip link set veth-a netns "$A_NS"
run ip link set veth-c netns "$C_NS"
run ip -n "$A_NS" addr add "$A_OUT/64" dev veth-a nodad
run ip -n "$C_NS" addr add "$C_OUT/64" dev veth-c nodad
run ip -n "$A_NS" link set veth-a up
run ip -n "$C_NS" link set veth-c up

note "each node owns a different /64, so the peer prefix needs an on-link route"
run ip -n "$A_NS" route add "$C_PFX" dev veth-a
run ip -n "$C_NS" route add "$A_PFX" dev veth-c

if ip netns exec "$A_NS" ping -6 -c2 -W2 "$C_OUT" >/dev/null 2>&1; then
  ok "a ($A_OUT) reaches c ($C_OUT)"
else
  die "underlay unreachable - stop here"
fi

pause
# ===========================================================================
say "Per-SA keys, derived from a per-VNI master key"
note "four SAs, four DIFFERENT keys. a->c and c->a must never share key+salt,"
note "or AES-GCM reuses nonces and the encryption is broken."

K42_AC=$(sa_key 42 a c);  K42_CA=$(sa_key 42 c a)
K77_AC=$(sa_key 77 a c);  K77_CA=$(sa_key 77 c a)

printf '    %-16s %s\n' "vni 42 a->c" "$K42_AC"
printf '    %-16s %s\n' "vni 42 c->a" "$K42_CA"
printf '    %-16s %s\n' "vni 77 a->c" "$K77_AC"
printf '    %-16s %s\n' "vni 77 c->a" "$K77_CA"

UNIQ=$(printf '%s\n%s\n%s\n%s\n' "$K42_AC" "$K42_CA" "$K77_AC" "$K77_CA" | sort -u | wc -l)
[ "$UNIQ" -eq 4 ] && pass "4 distinct keys" || fail "only $UNIQ distinct keys"

pause
# ===========================================================================
say "Mark rules: outer source /64 -> sender node id"
note "one rule per peer, independent of VNI count - the SPI separates VNIs,"
note "so the mark only has to say WHO sent the packet"

ip netns exec "$A_NS" nft -f - <<EOF
table inet vnimesh {
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    meta l4proto esp ip6 saddr $C_PFX counter meta mark set $C_ID
  }
}
EOF
[ $? -eq 0 ] && ok "node a: mark $C_ID for ESP from $C_PFX" || fail "node a mark rule"

ip netns exec "$C_NS" nft -f - <<EOF
table inet vnimesh {
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    meta l4proto esp ip6 saddr $A_PFX counter meta mark set $A_ID
  }
}
EOF
[ $? -eq 0 ] && ok "node c: mark $A_ID for ESP from $A_PFX" || fail "node c mark rule"

pause
# ===========================================================================
# One function, called four times - two VNIs x two directions. Every argument
# is visible at the call site below.
setup_side() {
  local vni=$1 me=$2 peer=$3 me_ns=$4
  local ifid;  ifid=$(vni_ifid "$vni")
  local me_o;  me_o=$(node_outer "$me")
  local pe_o;  pe_o=$(node_outer "$peer")
  local me_ov; me_ov=$(ovl_addr "$vni" "$me")
  local me_net; me_net=$(ovl_net "$vni" "$me")
  local pe_net; pe_net=$(ovl_net "$vni" "$peer")
  local pe_id; pe_id=$(node_id "$peer")

  run ip -n "$me_ns" link add "ipsec-$vni" type xfrm dev "veth-$me" if_id "$ifid"
  run ip -n "$me_ns" link set "ipsec-$vni" up
  run ip -n "$me_ns" link set "ipsec-$vni" mtu 1400
  run ip -n "$me_ns" addr add "$me_ov/128" dev "ipsec-$vni" nodad

  # OUTBOUND. No mark: the destination address already picks the peer.
  run ip -n "$me_ns" xfrm state add \
      src "$me_o" dst "$pe_o" \
      proto esp spi "$vni" reqid "$vni" mode tunnel if_id "$ifid" \
      replay-window 64 \
      aead 'rfc4106(gcm(aes))' "$(sa_key "$vni" "$me" "$peer")" 128 \
      sel src "$me_net" dst "$pe_net"

  # INBOUND. Mark carries the SENDER id. Redundant with two nodes, essential
  # with three or more, and free either way.
  run ip -n "$me_ns" xfrm state add \
      src "$pe_o" dst "$me_o" \
      proto esp spi "$vni" reqid "$vni" mode tunnel if_id "$ifid" \
      mark "$pe_id" mask 0xff output-mark 0x0 mask 0xff \
      replay-window 64 \
      aead 'rfc4106(gcm(aes))' "$(sa_key "$vni" "$peer" "$me")" 128 \
      sel src "$pe_net" dst "$me_net"

  run ip -n "$me_ns" xfrm policy add dir out if_id "$ifid" \
      src "$me_net" dst "$pe_net" \
      tmpl src "$me_o" dst "$pe_o" proto esp reqid "$vni" mode tunnel
  run ip -n "$me_ns" xfrm policy add dir in if_id "$ifid" \
      src "$pe_net" dst "$me_net" \
      tmpl src "$pe_o" dst "$me_o" proto esp reqid "$vni" mode tunnel

  run ip -n "$me_ns" route add "$pe_net" dev "ipsec-$vni" src "$me_ov"
}

say "VNI 42 on node a"; setup_side 42 a c "$A_NS"
say "VNI 42 on node c"; setup_side 42 c a "$C_NS"
pause
say "VNI 77 on node a"; setup_side 77 a c "$A_NS"
say "VNI 77 on node c"; setup_side 77 c a "$C_NS"

pause
# ===========================================================================
say "Everything node a now has"
note "4 states, 4 policies, 2 interfaces, 1 mark rule"
echo
printf '  %sSTATES%s\n' "$C_B" "$C_0"
ip -n "$A_NS" xfrm state | sed 's/^/    /'
echo
printf '  %sPOLICIES%s\n' "$C_B" "$C_0"
ip -n "$A_NS" xfrm policy | sed 's/^/    /'
echo
printf '  %sINTERFACES AND ROUTES%s\n' "$C_B" "$C_0"
ip -n "$A_NS" -br addr show type xfrm | sed 's/^/    /'
ip -n "$A_NS" -6 route show | grep -v '^fe80\|^ff00' | sed 's/^/    /'

pause
# ===========================================================================
say "Verification 1: both tenants pass traffic"
for vni in 42 77; do
  if ip netns exec "$A_NS" ping -6 -c3 -i 0.2 -W2 "$(ovl_addr "$vni" c)" >/dev/null 2>&1
  then pass "vni $vni: a -> c"; else fail "vni $vni: a -> c"; fi
  if ip netns exec "$C_NS" ping -6 -c3 -i 0.2 -W2 "$(ovl_addr "$vni" a)" >/dev/null 2>&1
  then pass "vni $vni: c -> a"; else fail "vni $vni: c -> a"; fi
done

say "Verification 2: SPI on the wire is exactly the VNI"
if command -v tcpdump >/dev/null 2>&1; then
  ip netns exec "$A_NS" timeout 6 tcpdump -ni veth-a -c 2 esp >/tmp/vni42.txt 2>/dev/null &
  P=$!; sleep 1
  ip netns exec "$A_NS" ping -6 -c2 -i 0.3 -W1 "$(ovl_addr 42 c)" >/dev/null 2>&1
  wait $P 2>/dev/null
  sed 's/^/    /' /tmp/vni42.txt

  ip netns exec "$A_NS" timeout 6 tcpdump -ni veth-a -c 2 esp >/tmp/vni77.txt 2>/dev/null &
  P=$!; sleep 1
  ip netns exec "$A_NS" ping -6 -c2 -i 0.3 -W1 "$(ovl_addr 77 c)" >/dev/null 2>&1
  wait $P 2>/dev/null
  sed 's/^/    /' /tmp/vni77.txt

  grep -q '0x0000002a' /tmp/vni42.txt && pass "vni 42 traffic carries spi 0x2a (42)" \
    || fail "vni 42 spi not seen on the wire"
  grep -q '0x0000004d' /tmp/vni77.txt && pass "vni 77 traffic carries spi 0x4d (77)" \
    || fail "vni 77 spi not seen on the wire"
else
  note "tcpdump not installed - skipped"
fi

say "Verification 3: tenant isolation"
rx() { ip -n "$A_NS" -s link show "ipsec-$1" | awk '/RX:/{getline; print $2; exit}'; }
B77=$(rx 77)
note "ipsec-77 RX bytes before: $B77"
note "20 pings on VNI 42..."
ip netns exec "$A_NS" ping -6 -c20 -i 0.1 -W1 "$(ovl_addr 42 c)" >/dev/null 2>&1
A77=$(rx 77)
note "ipsec-77 RX bytes after:  $A77"
[ "${B77:-0}" -eq "${A77:-1}" ] \
  && pass "no VNI-42 traffic surfaced on ipsec-77" \
  || fail "ipsec-77 moved by $((A77 - B77)) bytes during VNI-42 traffic"

say "Verification 4: anti-replay"
note "a window above 32 uses the BMP implementation, so the legacy field reads"
note "0 and the real window is in the context block - check the underscore name"
RW=$(ip -n "$A_NS" xfrm state | grep -c 'replay_window 64' || true)
[ "$RW" -eq 4 ] && pass "all 4 states have a 64-packet window" \
                || fail "expected 4 states with replay_window 64, found $RW"
ip -n "$A_NS" xfrm state | grep -A2 'anti-replay esn context' | head -3 | sed 's/^/    /'

say "Verification 5: a wrong key is dropped, not leaked"
BEFORE=$(xstat "$C_NS" XfrmInStateProtoError); BEFORE=${BEFORE:-0}
ip -n "$C_NS" xfrm state delete src "$A_OUT" dst "$C_OUT" proto esp spi 42 \
    mark "$A_ID" mask 0xff 2>/dev/null
ip -n "$C_NS" xfrm state add src "$A_OUT" dst "$C_OUT" \
    proto esp spi 42 reqid 42 mode tunnel if_id "$(vni_ifid 42)" \
    mark "$A_ID" mask 0xff output-mark 0x0 mask 0xff replay-window 64 \
    aead 'rfc4106(gcm(aes))' 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef 128 \
    sel src "$(ovl_net 42 a)" dst "$(ovl_net 42 c)" 2>/dev/null
ip netns exec "$A_NS" ping -6 -c3 -i 0.2 -W1 "$(ovl_addr 42 c)" >/dev/null 2>&1
AFTER=$(xstat "$C_NS" XfrmInStateProtoError); AFTER=${AFTER:-0}
[ "$AFTER" -gt "$BEFORE" ] \
  && pass "wrong key -> XfrmInStateProtoError +$((AFTER - BEFORE))" \
  || fail "wrong key did not raise XfrmInStateProtoError"

note "restoring..."
ip -n "$C_NS" xfrm state delete src "$A_OUT" dst "$C_OUT" proto esp spi 42 \
    mark "$A_ID" mask 0xff 2>/dev/null
ip -n "$C_NS" xfrm state add src "$A_OUT" dst "$C_OUT" \
    proto esp spi 42 reqid 42 mode tunnel if_id "$(vni_ifid 42)" \
    mark "$A_ID" mask 0xff output-mark 0x0 mask 0xff replay-window 64 \
    aead 'rfc4106(gcm(aes))' "$K42_AC" 128 \
    sel src "$(ovl_net 42 a)" dst "$(ovl_net 42 c)" 2>/dev/null
ip netns exec "$A_NS" ping -6 -c2 -W2 "$(ovl_addr 42 c)" >/dev/null 2>&1 \
  && pass "restored" || fail "restore failed"

# ===========================================================================
echo
printf '%s================ VERDICT ================%s\n' "$C_B" "$C_0"
if [ "$FAILURES" -eq 0 ]; then
  printf '  %sALL CHECKS PASSED%s\n\n' "$C_G" "$C_0"
  echo "  Two tenants over one link. SPI = VNI on the wire. Per-SA keys,"
  echo "  64-packet replay windows, isolation holding under traffic."
  echo
  echo "  Next: ./10-vni-mesh.sh for the four-node version."
else
  printf '  %s%s CHECK(S) FAILED%s\n' "$C_R" "$FAILURES" "$C_0"
fi
printf '%s========================================%s\n' "$C_B" "$C_0"
echo
note "inspect:   ./show.sh node-a"
note "plaintext: ip netns exec node-a tcpdump -ni ipsec-42"
note "wire:      ip netns exec node-a tcpdump -ni veth-a esp"
note "teardown:  sudo ./99-cleanup.sh"
