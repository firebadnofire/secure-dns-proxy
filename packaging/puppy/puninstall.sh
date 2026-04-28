#!/bin/sh
set -u

pkg=secure-dns-proxy
pidfile=/var/run/$pkg.pid
config=/etc/$pkg/config.json

if [ -f "$pidfile" ]; then
	pid=$(sed 's/[^0-9].*$//' "$pidfile" 2>/dev/null | sed -n '1p' || true)
	if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null || true
	fi
	rm -f "$pidfile"
fi

if [ -f "$config" ]; then
	echo "leaving $config in place; remove it manually if it is no longer needed" >&2
fi

exit 0
