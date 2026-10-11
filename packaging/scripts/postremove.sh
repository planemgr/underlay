#!/bin/sh
[ -d /run/systemd/system ] || exit 0
systemctl daemon-reload
exit 0
