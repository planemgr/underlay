#!/bin/sh
# Runs the daemon the way systemd would: restarted when it exits, so the test can restart the
# daemon alone (pkill underlay) as opposed to the whole node (restarting the container).
set -eu
# Containers behind the test NAT route through the router instead of Docker's gateway
if [ -n "${GATEWAY:-}" ]; then
  ip route replace default via "$GATEWAY"
fi
while true; do
  underlay || true
  sleep 1
done
