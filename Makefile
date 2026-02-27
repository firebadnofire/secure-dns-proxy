# Makefile for packaging secure-dns-proxy as a tarball
# -----------------------------------------------------

# metadata
PREFIX      := secure-dns-proxy
VERSION     := $(shell git describe --tags --always 2>/dev/null || echo "dev")
DISTDIR     := dist
STAGEDIR    := build/stage
BUILD_BIN   := build/$(PREFIX)

# staging subdirs
BIN_STG     := $(STAGEDIR)/$(PREFIX)/bin
CONF_STG    := $(STAGEDIR)/$(PREFIX)/etc/$(PREFIX)

# source config
EXAMPLE_CONF := config.example.json
DEFAULT_CONF := config.default.json

# install paths
INSTALL_PREFIX ?= /usr/local
SYSTEMD_UNIT_DIR ?= /etc/systemd/system
SYSCTL_DIR ?= /etc/sysctl.d
INSTALL ?= install

SYSTEMD_SERVICE := packaging/systemd/$(PREFIX).service
SYSCTL_CONF     := packaging/sysctl/$(PREFIX).conf

.PHONY: all package stage build install upgrade uninstall deinstall clean

# default target: build the package only
package: $(DISTDIR)/$(PREFIX)-$(VERSION).tar.gz

# explicit build target
build: $(BUILD_BIN)

# build the binary
$(BUILD_BIN):
	mkdir -p $(dir $@)
	go build -o $@ ./cmd/$(PREFIX)

# stage binary
$(BIN_STG): $(BUILD_BIN)
	mkdir -p $@
	cp $(BUILD_BIN) $(BIN_STG)/$(PREFIX)

# stage config
$(CONF_STG):
	mkdir -p $@
	cp $(EXAMPLE_CONF) $(CONF_STG)/config.example.json
	cp $(DEFAULT_CONF) $(CONF_STG)/config.json

# assemble staging tree
stage: $(BIN_STG) $(CONF_STG)

# create tarball
$(DISTDIR)/$(PREFIX)-$(VERSION).tar.gz: stage
	mkdir -p $(DISTDIR)
	tar -czf $@ -C $(STAGEDIR) $(PREFIX)

# build package, then install
all: package install

# install assumes the binary already exists
install:
	@test -x $(BUILD_BIN) || { echo "error: binary not built; run 'make build' or 'make' first"; exit 1; }
	getent group $(PREFIX) >/dev/null 2>&1 || groupadd -r $(PREFIX)
	id -u $(PREFIX) >/dev/null 2>&1 || \
	useradd -r -g $(PREFIX) -s /usr/sbin/nologin -d /nonexistent -M $(PREFIX)
	$(INSTALL) -d $(DESTDIR)$(INSTALL_PREFIX)/bin
	$(INSTALL) -m 0755 $(BUILD_BIN) $(DESTDIR)$(INSTALL_PREFIX)/bin/$(PREFIX)
	command -v setcap >/dev/null 2>&1 && \
	setcap 'cap_net_bind_service=+ep' $(DESTDIR)$(INSTALL_PREFIX)/bin/$(PREFIX) || \
	echo "setcap not available; ensure the binary can bind to privileged ports"
	$(INSTALL) -d -m 0750 -o $(PREFIX) -g $(PREFIX) $(DESTDIR)/etc/$(PREFIX)
	$(INSTALL) -m 0644 $(EXAMPLE_CONF) $(DESTDIR)/etc/$(PREFIX)/config.example.json
	[ -f $(DESTDIR)/etc/$(PREFIX)/config.json ] || \
	$(INSTALL) -m 0640 -o $(PREFIX) -g $(PREFIX) $(DEFAULT_CONF) $(DESTDIR)/etc/$(PREFIX)/config.json
	$(INSTALL) -d $(DESTDIR)$(SYSTEMD_UNIT_DIR)
	$(INSTALL) -m 0644 $(SYSTEMD_SERVICE) $(DESTDIR)$(SYSTEMD_UNIT_DIR)/$(PREFIX).service
	$(INSTALL) -d $(DESTDIR)$(SYSCTL_DIR)
	$(INSTALL) -m 0644 $(SYSCTL_CONF) $(DESTDIR)$(SYSCTL_DIR)/80-$(PREFIX).conf
	[ -z "$(DESTDIR)" ] && sysctl -q -w net.core.rmem_max=8388608 net.core.rmem_default=8388608 net.core.wmem_max=8388608 net.core.wmem_default=8388608 || true

upgrade:
	@test -x $(BUILD_BIN) || { echo "error: binary not built"; exit 1; }
	$(INSTALL) -d $(DESTDIR)$(INSTALL_PREFIX)/bin
	$(INSTALL) -m 0755 $(BUILD_BIN) $(DESTDIR)$(INSTALL_PREFIX)/bin/$(PREFIX)
	command -v setcap >/dev/null 2>&1 && \
	setcap 'cap_net_bind_service=+ep' $(DESTDIR)$(INSTALL_PREFIX)/bin/$(PREFIX) || \
	echo "setcap not available; ensure the binary can bind to privileged ports"

uninstall deinstall:
	rm -f $(DESTDIR)$(INSTALL_PREFIX)/bin/$(PREFIX)
	rm -f $(DESTDIR)/etc/$(PREFIX)/config.json $(DESTDIR)/etc/$(PREFIX)/config.example.json
	rmdir --ignore-fail-on-non-empty $(DESTDIR)/etc/$(PREFIX) 2>/dev/null || true
	rm -f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/$(PREFIX).service
	rm -f $(DESTDIR)$(SYSCTL_DIR)/80-$(PREFIX).conf
	userdel $(PREFIX) 2>/dev/null || true
	groupdel $(PREFIX) 2>/dev/null || true

clean:
	rm -rf build $(DISTDIR)
