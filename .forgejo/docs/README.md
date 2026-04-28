# secure-dns-proxy Forgejo Release Workflow

The release workflow lives at `.forgejo/workflows/build.yml`. It runs when a
version tag matching `v*` or `V*` is pushed.

The workflow builds these release assets for `amd64` and `arm64`:

- systemd tarballs: `secure-dns-proxy-${tag}-linux-${arch}-systemd.tar.gz`
- OpenRC tarballs: `secure-dns-proxy-${tag}-linux-${arch}-openrc.tar.gz`
- Puppy PET packages: `secure-dns-proxy-${tag}-puppy-${pet_arch}.pet`
- Debian packages: `secure-dns-proxy-${tag}-debian-${deb_arch}.deb`
- RPM packages: `secure-dns-proxy-${tag}-fedora-${rpm_arch}.rpm`

The workflow publishes the same asset set to Forgejo and to
`github.com/firebadnofire/secure-dns-proxy`.

## Required Secret

`GH_KEY` must be available to the Forgejo workflow. It is used to migrate refs to
GitHub and create or update GitHub releases. Do not hardcode this token.

## Validation

Before pushing a release tag, run:

```sh
ruby -e 'require "yaml"; YAML.load_file(".forgejo/workflows/build.yml"); puts "yaml ok"'
go test ./...
make -n pet deb rpm openrc-package
```

The `.deb` target requires `dpkg-deb`; the `.rpm` target requires `rpmbuild`.
The workflow installs these tools in its Ubuntu job container.
