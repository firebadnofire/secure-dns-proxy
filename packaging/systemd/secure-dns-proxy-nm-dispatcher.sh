#!/bin/sh
# NetworkManager dispatcher script to reload secure-dns-proxy when connectivity changes.

SERVICE=secure-dns-proxy.service

case "$2" in
  up|down|dhcp-change|vpn-up|vpn-down)
    if systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
      systemctl reload "$SERVICE"
    fi
    ;;
  *)
    ;; # ignore other events
esac
