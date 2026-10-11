#!/bin/sh
rc-service underlay stop 2>/dev/null
rc-update -a del underlay 2>/dev/null
exit 0
