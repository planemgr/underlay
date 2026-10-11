#!/usr/bin/env bash
# End-to-end test of the topology in compose.yaml:
#   1. every node reaches every other node's mesh address, NATed ones included
#   2. a restarted daemon keeps the node's key and tunnels
#   3. rebooted nodes (new keys) rejoin with their old mesh addresses
#   4. with a node down, the mesh keeps working and a new node still joins
#   5. after every node reboots at once, the cluster forms again with the same addresses
# KEEP=1 leaves the containers running afterwards.
set -euo pipefail
cd "$(dirname "$0")"

compose() { docker compose -p underlay-test "$@"; }

cleanup() {
  if [ "${KEEP:-}" != 1 ]; then
    compose --profile late down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  for n in $(compose ps --services); do
    echo "--- $n" >&2
    compose logs --tail 30 "$n" >&2 || true
  done
  exit 1
}

# What the kernel says: the daemon has no state or interface of its own to ask
mesh_ip() { compose exec -T "$1" ip -o addr show dev underlay0 2>/dev/null | awk '{print $4; exit}' | cut -d/ -f1; }
public_key() { compose exec -T "$1" wg show underlay0 public-key 2>/dev/null; }

# "name=ip" for each node
addresses() {
  local n
  for n in "$@"; do echo "$n=$(mesh_ip "$n")"; done
}

# "name=key" for each node
keys() {
  local n
  for n in "$@"; do echo "$n=$(public_key "$n")"; done
}

# Fails unless every node in "$@" has a key other than in $1 (a `keys` listing)
new_keys() {
  local before=$1 n
  shift
  for n in "$@"; do
    if grep -qx "$(keys "$n")" <<<"$before"; then fail "$n kept its key across a reboot"; fi
  done
  echo "  new keys: $*"
}

# Fails unless every node in "$@" has the key it had in $1
same_keys() {
  local before=$1 n
  shift
  for n in "$@"; do
    grep -qx "$(keys "$n")" <<<"$before" || fail "$n has a new key"
  done
  echo "  same keys: $*"
}

# Whether every node in "$@" can ping every other one's mesh address
full_mesh() {
  local ips=() a b i j ip
  for a in "$@"; do
    ip=$(mesh_ip "$a") || return 1
    [ -n "$ip" ] || return 1
    ips+=("$ip")
  done
  i=0
  for a in "$@"; do
    j=0
    for b in "$@"; do
      if [ "$i" != "$j" ]; then
        compose exec -T "$a" ping -c1 -W1 "${ips[$j]}" >/dev/null 2>&1 || { echo "  $a -> $b (${ips[$j]}) not yet"; return 1; }
      fi
      j=$((j + 1))
    done
    i=$((i + 1))
  done
}

wait_full_mesh() {
  local deadline=$((SECONDS + ${TIMEOUT:-180}))
  until full_mesh "$@"; do
    [ "$SECONDS" -lt "$deadline" ] || fail "no full mesh between $*"
    sleep 3
  done
  echo "  full mesh: $*"
}

same_addresses() {
  local before=$1
  shift
  local after
  after=$(addresses "$@")
  [ "$before" = "$after" ] || fail "mesh addresses changed:"$'\n'"$before"$'\n'"->"$'\n'"$after"
  echo "  same mesh addresses: $*"
}

# Each node's peers by name, at the endpoint WireGuard uses for them
summary() {
  local table n line
  table=$(addresses "$@")
  for n in "$@"; do
    line="$n $(mesh_ip "$n"):"
    while read -r _ _ endpoint allowed _; do
      line="$line $(grep "=${allowed%/*}\$" <<<"$table" | cut -d= -f1)@$endpoint"
    done < <(compose exec -T "$n" wg show underlay0 dump | tail -n +2)
    echo "  $line"
  done
}

NODES=(pub0 pub1 pub2 nat0 nat1)

compose build
echo "UNDERLAY_JOIN_TOKEN=ul2:$(head -c 32 /dev/urandom | base64):100.64.0.0/10" >join.env

echo "== 1. full mesh"
compose up -d
wait_full_mesh "${NODES[@]}"
summary "${NODES[@]}"
before=$(addresses "${NODES[@]}")
before_keys=$(keys "${NODES[@]}")

echo "== 2. daemon restarts"
compose exec -T pub1 pkill -x underlay
compose exec -T nat1 pkill -x underlay
sleep 3
wait_full_mesh "${NODES[@]}"
same_keys "$before_keys" pub1 nat1
same_addresses "$before" "${NODES[@]}"

echo "== 3. reboots"
compose restart nat0 pub0
wait_full_mesh "${NODES[@]}"
same_addresses "$before" "${NODES[@]}"
new_keys "$before_keys" nat0 pub0

echo "== 4. a node down, a node joining"
compose stop pub0
wait_full_mesh pub1 pub2 nat0 nat1
compose --profile late up -d pub3
wait_full_mesh pub1 pub2 nat0 nat1 pub3
compose start pub0
wait_full_mesh "${NODES[@]}" pub3
before=$(addresses "${NODES[@]}" pub3)
before_keys=$(keys "${NODES[@]}" pub3)

echo "== 5. everyone reboots"
compose restart "${NODES[@]}" pub3
wait_full_mesh "${NODES[@]}" pub3
same_addresses "$before" "${NODES[@]}" pub3
new_keys "$before_keys" "${NODES[@]}" pub3
summary "${NODES[@]}" pub3
echo "  how it re-formed:"
compose logs --no-log-prefix --since 5m "${NODES[@]}" pub3 2>/dev/null |
  grep -oE "(starting the cluster as|merged with|admitted by|rejoined with a new key|refused|recovered the roster).*" | sort | uniq -c | sed 's/^/   /'

echo "PASS"
