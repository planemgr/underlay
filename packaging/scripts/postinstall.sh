#!/bin/sh
[ -d /run/systemd/system ] || exit 0
systemctl daemon-reload
if [ "$1" = 2 ] || { [ "$1" = configure ] && [ -n "$2" ]; }; then
  systemctl try-restart underlay.service
fi
exit 0
