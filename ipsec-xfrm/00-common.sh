#!/usr/bin/env bash
# Shared config and helpers. Sourced by every script; not run directly.

# ---- identity ------------------------------------------------------------
# Node id -> mark value. The mark identifies the SENDER, nothing else.
# Underlay /64 per node; overlay /64 per (vni, node).
#
#   node   underlay              mark   vni 42 overlay   vni 77 overlay
#   a      2001:db8:aa::/64      0x1    fd2a:a::/64      fd4d:a::/64
#   b      2001:db8:bb::/64      0x2    fd2a:b::/64      -
#   c      2001:db8:cc::/64      0x3    fd2a:c::/64      fd4d:c::/64
#   d      2001:db8:dd::/64      0x4    fd2a:d::/64      fd4d:d::/64

EPOCH=1

node_ns()    { echo "node-$1"; }
node_id()    { case $1 in a) echo 0x1;; b) echo 0x2;; c) echo 0x3;; d) echo 0x4;; esac; }
node_outer() { case $1 in a) echo 2001:db8:aa::1;; b) echo 2001:db8:bb::1;;
                          c) echo 2001:db8:cc::1;; d) echo 2001:db8:dd::1;; esac; }
node_opfx()  { case $1 in a) echo 2001:db8:aa::/64;; b) echo 2001:db8:bb::/64;;
                          c) echo 2001:db8:cc::/64;; d) echo 2001:db8:dd::/64;; esac; }

# SPI is exactly the VNI. if_id is the VNI in hex (42 -> 0x2a, 77 -> 0x4d).
vni_pfx()    { case $1 in 42) echo fd2a;; 77) echo fd4d;; esac; }
vni_ifid()   { case $1 in 42) echo 0x2a;; 77) echo 0x4d;; esac; }
ovl_addr()   { echo "$(vni_pfx "$1"):$2::1"; }
ovl_net()    { echo "$(vni_pfx "$1"):$2::/64"; }

# ---- per-SA key derivation ------------------------------------------------
# Returns 20 bytes: 16-byte AES-128 key + 4-byte GCM salt.
#
# This is NOT optional. AES-GCM builds its nonce from salt||sequence, so two
# SAs that share a key and both start at sequence 1 emit identical nonces -
# which under GCM leaks the XOR of the plaintexts and enables tag forgery.
# Deriving per-SA material keeps "one key per VNI" as the operational model
# while giving every SA distinct key+salt.
#
# Lab-grade derivation. Production: HKDF-Expand with a proper label, and real
# key distribution rather than a hardcoded master string.
sa_key() {  # vni sender receiver
  local ctx="vni$1-from$2-to$3-epoch$EPOCH" h
  if command -v openssl >/dev/null 2>&1; then
    h=$(printf '%s' "$ctx" | openssl dgst -sha256 -hmac "master-key-vni-$1" | awk '{print $NF}')
  else
    h=$(printf '%s' "master-key-vni-$1-$ctx" | sha256sum | awk '{print $1}')
  fi
  printf '0x%s' "${h:0:40}"
}

# ---- output helpers -------------------------------------------------------
if [ -t 1 ]; then
  C_DIM=$'\033[2m'; C_B=$'\033[1m'; C_G=$'\033[32m'; C_R=$'\033[31m'
  C_Y=$'\033[33m'; C_0=$'\033[0m'
else
  C_DIM=; C_B=; C_G=; C_R=; C_Y=; C_0=
fi

say()  { printf '\n%s==>%s %s%s%s\n' "$C_B" "$C_0" "$C_B" "$*" "$C_0"; }
note() { printf '    %s%s%s\n' "$C_DIM" "$*" "$C_0"; }
ok()   { printf '    %s[ok]%s %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '    %s[!!]%s %s\n' "$C_Y" "$C_0" "$*"; }
die()  { printf '    %s[xx]%s %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }

run() { printf '  %s$ %s%s\n' "$C_DIM" "$*" "$C_0"; "$@"; }
try() { printf '  %s$ %s%s\n' "$C_DIM" "$*" "$C_0"; "$@" || true; }

pause() {
  [ -n "${NOPAUSE:-}" ] && return 0
  printf '\n    %s-- press enter to continue --%s' "$C_DIM" "$C_0"
  read -r _ || true
  printf '\n'
}

need_root() { [ "$(id -u)" -eq 0 ] || die "run this as root (sudo $0)"; }

# ---- xfrm inspection ------------------------------------------------------
xstat() {
  ip netns exec "$1" cat /proc/net/xfrm_stat 2>/dev/null \
    | awk -v k="$2" '$1==k{print $2}' | head -1
}

xstat_nonzero() {
  local out
  out=$(ip netns exec "$1" cat /proc/net/xfrm_stat 2>/dev/null | awk '$2>0')
  if [ -z "$out" ]; then
    note "($1) all xfrm error counters are zero"
  else
    printf '%s\n' "$out" | sed "s/^/    ($1) /"
  fi
}

# Packets processed by the state whose 'src' line matches $2.
# Anchored to the 'lifetime current' block: 'ip -s xfrm state' prints
# "(packets)" twice, and the lifetime CONFIG block says "(INF)(packets)".
sa_packets_src() {
  local n
  n=$(ip -n "$1" -s xfrm state 2>/dev/null | awk -v s="$2" '
        $1=="src" && $2==s  { insa=1; cur=0; next }
        $1=="src" && $2!=s  { insa=0 }
        insa && /lifetime current/ { cur=1; next }
        insa && cur && /\(packets\)/ { gsub(/[(),]/," "); print $3; exit }
      ' | head -1)
  case "$n" in ''|*[!0-9]*) n=0 ;; esac
  printf '%s' "$n"
}
