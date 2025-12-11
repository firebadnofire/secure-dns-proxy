#!/bin/sh
# NetworkManager dispatcher script to reload secure-dns-proxy when connectivity changes.

SERVICE=secure-dns-proxy.service

case "$2" in
  up|down|dhcp-change|vpn-up|vpn-down)
    if systemctl is-enabled --quiet "$SERVICE" 2>/dev/null || systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
      systemctl try-reload-or-restart "$SERVICE"
    fi
    ;;
  *)
    ;; # ignore other events
esac
