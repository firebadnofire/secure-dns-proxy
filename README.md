# secure-dns-proxy

`secure-dns-proxy` binary that proxies DNS

`upstreams-example.conf` conf to copy to etc/upstreams.conf with changes

[x] Standard DNS support
[x] DNS over HTTPS (DoH) support 
[x] DNS over TLS (DoT) support
[x] DNS over QUIC (DoQ) support

Build instructions:

```
git clone https://codeberg.org/firebadnofire/secure-dns-proxy
cd secure-dns-proxy
CHANGE ME LATER YOU LAZY BUM
```

# Notes

This project is licensed under the [GNU Affero General Public License](https://www.gnu.org/licenses/agpl-3.0.en.html). [Know your rights](https://choosealicense.com/licenses/agpl-3.0/).

There is a `--insecure` flag you can use at runtime (eg. `sudo ./secure-dns-proxy --insecure`) that will disable TLS certificate verification. You should NEVER need to use this unless you are testing something, in which you should know very well what you are about to do.
