#!/bin/sh
set -eu

pkg=secure-dns-proxy
bin=/usr/local/bin/$pkg
config_dir=/etc/$pkg
config=$config_dir/config.toml
default_config=/usr/share/$pkg/config.default.toml
example_config=$config_dir/config.example.toml
init_script=/etc/init.d/$pkg

if [ ! -x "$bin" ]; then
	echo "error: missing executable $bin" >&2
	exit 1
fi

if [ ! -f "$default_config" ]; then
	echo "error: missing default configuration $default_config" >&2
	exit 1
fi

mkdir -p "$config_dir"

if [ ! -f "$config" ]; then
	cp "$default_config" "$config"
	chmod 0644 "$config"
	echo "created default configuration at $config"
else
	echo "preserved existing configuration at $config"
fi

if [ -f "$example_config" ]; then
	chmod 0644 "$example_config" || true
fi

chmod 0755 "$bin"

if [ -f "$init_script" ]; then
	chmod 0755 "$init_script"
fi

if command -v setcap >/dev/null 2>&1; then
	if setcap 'cap_net_bind_service=+ep' "$bin" >/dev/null 2>&1; then
		echo "granted CAP_NET_BIND_SERVICE to $bin"
	else
		echo "warning: setcap failed; run $pkg as root or grant CAP_NET_BIND_SERVICE to bind port 53" >&2
	fi
else
	echo "notice: setcap not available; $pkg must run as root or use an unprivileged port unless capabilities are granted another way" >&2
fi

cat <<EOF
$pkg installed.
Review $config before starting the daemon.
Start manually with: $bin --config $config
Optional init script: $init_script start
EOF

exit 0
