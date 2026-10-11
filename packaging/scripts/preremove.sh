#!/bin/sh
[ -d /run/systemd/system ] || exit 0
if [ "$1" = remove ] || [ "$1" = 0 ]; then
  systemctl disable --now underlay.service
fi
exit 0
