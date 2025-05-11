# secure-dns-proxy

`secure-dns-proxy` proxies DNS queries

## Why?

A lot of systems don't natively support DNS over HTTPS, DNS over TLS, and especially DNS over QUIC. This project aims to provide support for these transport layers without heavy system modifications. 

## How?

DoH, DoT, and DoQ are all layers that go over unencrypted or standard DNS, so all you really need to do is safely deliver them and unwrap them, so that's exactly what this does. Your computer makes a query to `127.0.0.35:53` and `secure-dns-proxy` will reach out to an upstream in `etc/upstreams.conf`, say `tls://doh.archuser.org`. The DoT host will reply in DoT, but when it reaches the system it is unwrapped into standard DNS. Since it is bound to `127.0.0.35`, no unencrypted data leaves the system. 

- [x] Standard DNS support
- [x] DNS over HTTPS (DoH) support 
- [x] DNS over TLS (DoT) support
- [x] DNS over QUIC (DoQ) support

## Build instructions

```
git clone https://codeberg.org/firebadnofire/secure-dns-proxy
cd secure-dns-proxy
make
```

The compiled build will be put in `dist/` as a `tar.gz` containing a portable build. You may run `sudo tar --strip-components=1 -C / -xaf file.tar.gz` to install it to your system

OR

`go install archuser.org/secure-dns-proxy@latest`

# Notes

This project is licensed under the [GNU Affero General Public License](https://www.gnu.org/licenses/agpl-3.0.en.html). [What is this]?(https://choosealicense.com/licenses/agpl-3.0/).

To enable pmtud, use `--pmtud`

To switch the bind address, use `--bind` (eg. `--bind 127.0.0.53`)

To switch the bind port, use `--port` (eg. `--port 54`)

`/etc/secure-dns-proxy/upstreams.conf` as well as `~/.config/secure-dns-proxy/upstreams.conf` are also valid conf locations.

There is a `--insecure` flag you can use at runtime (eg. `sudo ./secure-dns-proxy --insecure`) that will disable TLS certificate verification. You should NEVER need to use this unless you are testing something, in which you should know very well what you are about to do.
