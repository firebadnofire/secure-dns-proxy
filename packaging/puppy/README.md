# secure-dns-proxy Puppy Linux package

This PET package installs a Linux `secure-dns-proxy` binary, example
configuration, a default configuration template, and an optional init script for
Puppy Linux systems.

## Build

From the repository root:

```sh
make pet
```

The default target builds a Linux `amd64` binary and writes
`dist/secure-dns-proxy-<version>-puppy-x86_64.pet`.

For other Puppy architectures, override both the Go architecture and PET
architecture label:

```sh
make pet PET_GOARCH=386 PET_ARCH=i686
make pet PET_GOARCH=arm64 PET_ARCH=aarch64
```

## Install and run

Install the `.pet` through Puppy Package Manager or by opening it in Puppy. The
post-install script creates `/etc/secure-dns-proxy/config.json` only if it does
not already exist, so package upgrades preserve local resolver settings.

Review configuration before starting:

```sh
defaulttexteditor /etc/secure-dns-proxy/config.json
```

Start manually:

```sh
/usr/local/bin/secure-dns-proxy --config /etc/secure-dns-proxy/config.json
```

Or use the optional init script:

```sh
/etc/init.d/secure-dns-proxy start
/etc/init.d/secure-dns-proxy status
/etc/init.d/secure-dns-proxy stop
```

## Security notes

Puppy Linux commonly runs services as root and does not provide the systemd
sandboxing used by the tarball installer. The PET post-install script attempts
to grant `CAP_NET_BIND_SERVICE` with `setcap` when available, but some Puppy
installations or filesystems may not support file capabilities. If capabilities
cannot be granted, binding to DNS port 53 requires root or a custom
configuration that uses an unprivileged port.

This package does not apply sysctl tuning automatically. For high-volume DoQ
use, review the values in `packaging/sysctl/secure-dns-proxy.conf` and apply
equivalent settings manually if appropriate for the target Puppy system.
