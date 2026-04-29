# Makefile for packaging secure-dns-proxy as a tarball
# -----------------------------------------------------

# metadata
PREFIX      := secure-dns-proxy
VERSION     := $(shell git describe --tags --always 2>/dev/null || echo "dev")
DISTDIR     := dist
STAGEDIR    := build/stage
BUILD_BIN   := build/$(PREFIX)
PKG_VERSION := $(shell printf '%s' "$(VERSION)" | sed 's/^[vV]//; s/[^A-Za-z0-9.+~]/_/g')
PKG_RELEASE ?= 1
PKG_MAINTAINER ?= secure-dns-proxy maintainers
PKG_DESCRIPTION := Secure DNS proxy with DoH, DoT, and DoQ
LINUX_GODEBUG ?= goindex=0
LINUX_CGO_ENABLED ?= 0

# Puppy Linux PET package settings
PET_GOARCH ?= amd64
PET_ARCH ?= x86_64
PET_DISTRO ?= puppy-$(PET_ARCH)
PET_CATEGORY ?= Network
PET_PKG := $(PREFIX)-$(VERSION)-$(PET_DISTRO)
PET_STAGEDIR := build/pet
PET_ROOT := $(PET_STAGEDIR)/$(PET_PKG)
PET_BIN := build/$(PREFIX)-linux-$(PET_GOARCH)
PET_TGZ := $(PET_STAGEDIR)/$(PET_PKG).tar.gz
PET_FILE := $(DISTDIR)/$(PET_PKG).pet

# Debian package settings
DEB_GOARCH ?= amd64
DEB_ARCH ?= $(if $(filter 386,$(DEB_GOARCH)),i386,$(DEB_GOARCH))
DEB_DISTRO ?= debian-$(DEB_ARCH)
DEB_SYSTEMD_UNIT_DIR ?= /lib/systemd/system
DEB_PKG := $(PREFIX)-$(VERSION)-$(DEB_DISTRO)
DEB_STAGEDIR := build/deb
DEB_ROOT := $(DEB_STAGEDIR)/$(DEB_PKG)
DEB_BIN := build/$(PREFIX)-linux-$(DEB_GOARCH)
DEB_FILE := $(DISTDIR)/$(DEB_PKG).deb

# RPM package settings
RPM_GOARCH ?= amd64
RPM_ARCH ?= $(if $(filter amd64,$(RPM_GOARCH)),x86_64,$(if $(filter arm64,$(RPM_GOARCH)),aarch64,$(RPM_GOARCH)))
RPM_DISTRO ?= fedora-$(RPM_ARCH)
RPM_SYSTEMD_UNIT_DIR ?= /usr/lib/systemd/system
RPM_PKG := $(PREFIX)-$(VERSION)-$(RPM_DISTRO)
RPM_TOPDIR := build/rpm
RPM_PAYLOAD_ROOT := $(RPM_TOPDIR)/payload/$(RPM_PKG)
RPM_HOME := $(RPM_TOPDIR)/home
RPM_XDG_CONFIG_HOME := $(RPM_TOPDIR)/xdg
RPM_RPMRC := $(RPM_XDG_CONFIG_HOME)/rpm/rpmrc
RPM_LEGACY_RPMRC := $(RPM_HOME)/.rpmrc
RPM_SPEC := $(RPM_TOPDIR)/SPECS/$(RPM_PKG).spec
RPM_BIN := build/$(PREFIX)-linux-$(RPM_GOARCH)
RPM_FILE := $(DISTDIR)/$(RPM_PKG).rpm

# staging subdirs
BIN_STG     := $(STAGEDIR)/$(PREFIX)/bin
CONF_STG    := $(STAGEDIR)/$(PREFIX)/etc/$(PREFIX)
PKG_STG     := $(STAGEDIR)/$(PREFIX)/packaging

# OpenRC tarball staging
OPENRC_STAGEDIR := build/stage-openrc
OPENRC_BIN_STG := $(OPENRC_STAGEDIR)/$(PREFIX)/bin
OPENRC_CONF_STG := $(OPENRC_STAGEDIR)/$(PREFIX)/etc/$(PREFIX)
OPENRC_PKG_STG := $(OPENRC_STAGEDIR)/$(PREFIX)/packaging
OPENRC_MAKEFILE_STG := $(OPENRC_STAGEDIR)/$(PREFIX)/Makefile
OPENRC_README_STG := $(OPENRC_STAGEDIR)/$(PREFIX)/README.md
OPENRC_INIT_STG := $(OPENRC_PKG_STG)/openrc/$(PREFIX)
OPENRC_SYSCTL_CONF_STG := $(OPENRC_PKG_STG)/sysctl/$(PREFIX).conf
OPENRC_FILE := $(DISTDIR)/$(PREFIX)-$(VERSION)-openrc.tar.gz

# source config
EXAMPLE_CONF := config.example.json
DEFAULT_CONF := config.default.json
DIST_MAKEFILE := Makefile-dist
DIST_README := README-dist.md
OPENRC_DIST_MAKEFILE := Makefile-openrc-dist
OPENRC_DIST_README := README-openrc-dist.md

# install paths
INSTALL_PREFIX ?= /usr/local
SYSTEMD_UNIT_DIR ?= /etc/systemd/system
SYSCTL_DIR ?= /etc/sysctl.d
INSTALL ?= install

SYSTEMD_SERVICE := packaging/systemd/$(PREFIX).service
SYSCTL_CONF     := packaging/sysctl/$(PREFIX).conf
OPENRC_INIT := packaging/openrc/$(PREFIX)
PUPPY_PINSTALL := packaging/puppy/pinstall.sh
PUPPY_PUNINSTALL := packaging/puppy/puninstall.sh
PUPPY_INIT := packaging/puppy/$(PREFIX).init
PUPPY_README := packaging/puppy/README.md
DEB_POSTINST := packaging/deb/postinst
DEB_PRERM := packaging/deb/prerm
DEB_POSTRM := packaging/deb/postrm
DIST_MAKEFILE_STG := $(STAGEDIR)/$(PREFIX)/Makefile
DIST_README_STG := $(STAGEDIR)/$(PREFIX)/README.md
SYSTEMD_SERVICE_STG := $(PKG_STG)/systemd/$(PREFIX).service
SYSCTL_CONF_STG := $(PKG_STG)/sysctl/$(PREFIX).conf

.PHONY: all package openrc-package pet deb rpm stage openrc-stage pet-stage deb-stage rpm-stage build install upgrade uninstall deinstall clean

# default target: build the package only
package: $(DISTDIR)/$(PREFIX)-$(VERSION).tar.gz

# Puppy Linux PET package
pet: $(PET_FILE)

# Debian package
deb: $(DEB_FILE)

# RPM package
rpm: $(RPM_FILE)

# OpenRC binary release tarball
openrc-package: $(OPENRC_FILE)

# explicit build target
build: $(BUILD_BIN)

# build the binary
$(BUILD_BIN):
	mkdir -p $(dir $@)
	GODEBUG=$(LINUX_GODEBUG) go build -o $@ ./cmd/$(PREFIX)

# build the Linux binary used by Puppy PET packages
build/$(PREFIX)-linux-%:
	mkdir -p $(dir $@)
	GODEBUG=$(LINUX_GODEBUG) CGO_ENABLED=$(LINUX_CGO_ENABLED) GOOS=linux GOARCH=$* go build -trimpath -o $@ ./cmd/$(PREFIX)

# stage binary
$(BIN_STG): $(BUILD_BIN)
	mkdir -p $@
	cp $(BUILD_BIN) $(BIN_STG)/$(PREFIX)

# stage config
$(CONF_STG):
	mkdir -p $@
	cp $(EXAMPLE_CONF) $(CONF_STG)/config.example.json
	cp $(DEFAULT_CONF) $(CONF_STG)/config.json

# stage distribution installer as the tarball Makefile
$(DIST_MAKEFILE_STG): $(DIST_MAKEFILE)
	mkdir -p $(dir $@)
	cp $(DIST_MAKEFILE) $@

# stage binary release README
$(DIST_README_STG): $(DIST_README)
	mkdir -p $(dir $@)
	cp $(DIST_README) $@

# stage packaging metadata used by Makefile-dist
$(SYSTEMD_SERVICE_STG): $(SYSTEMD_SERVICE)
	mkdir -p $(dir $@)
	cp $(SYSTEMD_SERVICE) $@

$(SYSCTL_CONF_STG): $(SYSCTL_CONF)
	mkdir -p $(dir $@)
	cp $(SYSCTL_CONF) $@

# assemble staging tree
stage: $(BIN_STG) $(CONF_STG) $(DIST_MAKEFILE_STG) $(DIST_README_STG) $(SYSTEMD_SERVICE_STG) $(SYSCTL_CONF_STG)

# create tarball
$(DISTDIR)/$(PREFIX)-$(VERSION).tar.gz: stage
	mkdir -p $(DISTDIR)
	tar -czf $@ -C $(STAGEDIR) $(PREFIX)

# stage OpenRC binary release contents. This release uses its own installer
# Makefile and carries an OpenRC init script instead of a systemd unit.
openrc-stage: $(OPENRC_BIN_STG) $(OPENRC_CONF_STG) $(OPENRC_MAKEFILE_STG) $(OPENRC_README_STG) $(OPENRC_INIT_STG) $(OPENRC_SYSCTL_CONF_STG)

$(OPENRC_BIN_STG): $(BUILD_BIN)
	mkdir -p $@
	cp $(BUILD_BIN) $(OPENRC_BIN_STG)/$(PREFIX)

$(OPENRC_CONF_STG):
	mkdir -p $@
	cp $(EXAMPLE_CONF) $(OPENRC_CONF_STG)/config.example.json
	cp $(DEFAULT_CONF) $(OPENRC_CONF_STG)/config.json

$(OPENRC_MAKEFILE_STG): $(OPENRC_DIST_MAKEFILE)
	mkdir -p $(dir $@)
	cp $(OPENRC_DIST_MAKEFILE) $@

$(OPENRC_README_STG): $(OPENRC_DIST_README)
	mkdir -p $(dir $@)
	cp $(OPENRC_DIST_README) $@

$(OPENRC_INIT_STG): $(OPENRC_INIT)
	mkdir -p $(dir $@)
	cp $(OPENRC_INIT) $@

$(OPENRC_SYSCTL_CONF_STG): $(SYSCTL_CONF)
	mkdir -p $(dir $@)
	cp $(SYSCTL_CONF) $@

$(OPENRC_FILE): openrc-stage
	mkdir -p $(DISTDIR)
	tar -czf $@ -C $(OPENRC_STAGEDIR) $(PREFIX)

# stage Puppy PET package contents. The package installs files directly under /
# and lets pinstall.sh create config.json only when the user does not have one.
pet-stage: $(PET_ROOT)

$(PET_ROOT): $(PET_BIN) $(EXAMPLE_CONF) $(DEFAULT_CONF) LICENSE $(PUPPY_PINSTALL) $(PUPPY_PUNINSTALL) $(PUPPY_INIT) $(PUPPY_README)
	rm -rf $(PET_ROOT)
	mkdir -p $(PET_ROOT)/usr/local/bin
	mkdir -p $(PET_ROOT)/etc/$(PREFIX)
	mkdir -p $(PET_ROOT)/etc/init.d
	mkdir -p $(PET_ROOT)/usr/share/$(PREFIX)
	mkdir -p $(PET_ROOT)/usr/share/doc/$(PREFIX)
	cp $(PET_BIN) $(PET_ROOT)/usr/local/bin/$(PREFIX)
	chmod 0755 $(PET_ROOT)/usr/local/bin/$(PREFIX)
	cp $(EXAMPLE_CONF) $(PET_ROOT)/etc/$(PREFIX)/config.example.json
	cp $(DEFAULT_CONF) $(PET_ROOT)/usr/share/$(PREFIX)/config.default.json
	cp $(PUPPY_INIT) $(PET_ROOT)/etc/init.d/$(PREFIX)
	chmod 0755 $(PET_ROOT)/etc/init.d/$(PREFIX)
	cp $(PUPPY_PINSTALL) $(PET_ROOT)/pinstall.sh
	cp $(PUPPY_PUNINSTALL) $(PET_ROOT)/puninstall.sh
	chmod 0755 $(PET_ROOT)/pinstall.sh $(PET_ROOT)/puninstall.sh
	cp $(PUPPY_README) $(PET_ROOT)/usr/share/doc/$(PREFIX)/README-puppy.md
	cp LICENSE $(PET_ROOT)/usr/share/doc/$(PREFIX)/LICENSE
	size_k=$$(du -sk "$(PET_ROOT)" | awk '{print $$1}'); \
	printf '%s|%s|%s||%s|%sK||%s.pet||%s\n' \
		"$(PET_PKG)" "$(PREFIX)" "$(PKG_VERSION)" "$(PET_CATEGORY)" "$$size_k" "$(PET_PKG)" "$(PKG_DESCRIPTION)" \
		> "$(PET_ROOT)/pet.specs"

$(PET_TGZ): $(PET_ROOT)
	rm -f $@
	tar -czf $@ -C $(PET_ROOT) pet.specs pinstall.sh puninstall.sh usr etc

$(PET_FILE): $(PET_TGZ)
	mkdir -p $(DISTDIR)
	rm -f $@
	tmp="$@.tmp"; \
	cp "$(PET_TGZ)" "$$tmp"; \
	if command -v md5sum >/dev/null 2>&1; then \
		digest=$$(md5sum "$(PET_TGZ)" | awk '{print $$1}'); \
	elif command -v md5 >/dev/null 2>&1; then \
		digest=$$(md5 -q "$(PET_TGZ)"); \
	elif command -v openssl >/dev/null 2>&1; then \
		digest=$$(openssl dgst -md5 -r "$(PET_TGZ)" | awk '{print $$1}'); \
	else \
		echo "error: md5sum, md5, or openssl is required to build a PET package" >&2; \
		rm -f "$$tmp"; \
		exit 1; \
	fi; \
	printf '%s' "$$digest" >> "$$tmp"; \
	mv "$$tmp" "$@"

# Debian package. config.json is created by postinst only when absent, so
# package upgrades do not overwrite the active resolver configuration.
deb-stage: $(DEB_ROOT)

$(DEB_ROOT): $(DEB_BIN) $(EXAMPLE_CONF) $(DEFAULT_CONF) LICENSE $(SYSTEMD_SERVICE) $(SYSCTL_CONF) $(DEB_POSTINST) $(DEB_PRERM) $(DEB_POSTRM)
	rm -rf $(DEB_ROOT)
	mkdir -p $(DEB_ROOT)/DEBIAN
	mkdir -p $(DEB_ROOT)/usr/local/bin
	mkdir -p $(DEB_ROOT)/etc/$(PREFIX)
	mkdir -p $(DEB_ROOT)$(DEB_SYSTEMD_UNIT_DIR)
	mkdir -p $(DEB_ROOT)$(SYSCTL_DIR)
	mkdir -p $(DEB_ROOT)/usr/share/$(PREFIX)
	mkdir -p $(DEB_ROOT)/usr/share/doc/$(PREFIX)
	cp $(DEB_BIN) $(DEB_ROOT)/usr/local/bin/$(PREFIX)
	chmod 0755 $(DEB_ROOT)/usr/local/bin/$(PREFIX)
	cp $(EXAMPLE_CONF) $(DEB_ROOT)/etc/$(PREFIX)/config.example.json
	cp $(DEFAULT_CONF) $(DEB_ROOT)/usr/share/$(PREFIX)/config.default.json
	cp $(SYSTEMD_SERVICE) $(DEB_ROOT)$(DEB_SYSTEMD_UNIT_DIR)/$(PREFIX).service
	cp $(SYSCTL_CONF) $(DEB_ROOT)$(SYSCTL_DIR)/80-$(PREFIX).conf
	cp LICENSE $(DEB_ROOT)/usr/share/doc/$(PREFIX)/copyright
	cp $(DEB_POSTINST) $(DEB_ROOT)/DEBIAN/postinst
	cp $(DEB_PRERM) $(DEB_ROOT)/DEBIAN/prerm
	cp $(DEB_POSTRM) $(DEB_ROOT)/DEBIAN/postrm
	chmod 0755 $(DEB_ROOT)/DEBIAN/postinst $(DEB_ROOT)/DEBIAN/prerm $(DEB_ROOT)/DEBIAN/postrm
	installed_size=$$(du -sk "$(DEB_ROOT)" | awk '{print $$1}'); \
	{ \
		printf 'Package: %s\n' "$(PREFIX)"; \
		printf 'Version: %s\n' "$(PKG_VERSION)"; \
		printf 'Section: net\n'; \
		printf 'Priority: optional\n'; \
		printf 'Architecture: %s\n' "$(DEB_ARCH)"; \
		printf 'Maintainer: %s\n' "$(PKG_MAINTAINER)"; \
		printf 'Installed-Size: %s\n' "$$installed_size"; \
		printf 'Depends: ca-certificates\n'; \
		printf 'Recommends: libcap2-bin, systemd\n'; \
		printf 'Description: %s\n' "$(PKG_DESCRIPTION)"; \
		printf ' Local DNS stub resolver supporting plaintext DNS, DoH, DoT, and DoQ.\n'; \
	} > "$(DEB_ROOT)/DEBIAN/control"

$(DEB_FILE): $(DEB_ROOT)
	@command -v dpkg-deb >/dev/null 2>&1 || { echo "error: dpkg-deb is required to build $(DEB_FILE)" >&2; exit 1; }
	mkdir -p $(DISTDIR)
	rm -f $@
	dpkg-deb --root-owner-group --build "$(DEB_ROOT)" "$@"

# RPM package. The RPM payload mirrors the systemd package layout used by the
# tarball installer, with scriptlets for user creation and config preservation.
rpm-stage: $(RPM_PAYLOAD_ROOT) $(RPM_SPEC) $(RPM_RPMRC) $(RPM_LEGACY_RPMRC)

$(RPM_PAYLOAD_ROOT): $(RPM_BIN) $(EXAMPLE_CONF) $(DEFAULT_CONF) LICENSE $(SYSTEMD_SERVICE) $(SYSCTL_CONF)
	rm -rf $(RPM_PAYLOAD_ROOT)
	mkdir -p $(RPM_PAYLOAD_ROOT)/usr/local/bin
	mkdir -p $(RPM_PAYLOAD_ROOT)/etc/$(PREFIX)
	mkdir -p $(RPM_PAYLOAD_ROOT)$(RPM_SYSTEMD_UNIT_DIR)
	mkdir -p $(RPM_PAYLOAD_ROOT)$(SYSCTL_DIR)
	mkdir -p $(RPM_PAYLOAD_ROOT)/usr/share/$(PREFIX)
	mkdir -p $(RPM_PAYLOAD_ROOT)/usr/share/doc/$(PREFIX)
	cp $(RPM_BIN) $(RPM_PAYLOAD_ROOT)/usr/local/bin/$(PREFIX)
	chmod 0755 $(RPM_PAYLOAD_ROOT)/usr/local/bin/$(PREFIX)
	cp $(EXAMPLE_CONF) $(RPM_PAYLOAD_ROOT)/etc/$(PREFIX)/config.example.json
	cp $(DEFAULT_CONF) $(RPM_PAYLOAD_ROOT)/usr/share/$(PREFIX)/config.default.json
	cp $(SYSTEMD_SERVICE) $(RPM_PAYLOAD_ROOT)$(RPM_SYSTEMD_UNIT_DIR)/$(PREFIX).service
	cp $(SYSCTL_CONF) $(RPM_PAYLOAD_ROOT)$(SYSCTL_DIR)/80-$(PREFIX).conf
	cp LICENSE $(RPM_PAYLOAD_ROOT)/usr/share/doc/$(PREFIX)/LICENSE

$(RPM_SPEC): Makefile
	mkdir -p $(dir $@)
	{ \
		printf 'Name: %s\n' "$(PREFIX)"; \
		printf 'Version: %s\n' "$(PKG_VERSION)"; \
		printf 'Release: %s%%{?dist}\n' "$(PKG_RELEASE)"; \
		printf 'Summary: %s\n' "$(PKG_DESCRIPTION)"; \
		printf 'License: AGPL-3.0-or-later\n'; \
		printf 'BuildArch: %s\n' "$(RPM_ARCH)"; \
		printf 'AutoReqProv: no\n'; \
		printf 'Requires: ca-certificates\n'; \
		printf 'Requires(pre): shadow-utils\n'; \
		printf 'Requires(post): libcap\n'; \
		printf 'Requires(post): systemd\n'; \
		printf 'Requires(preun): systemd\n'; \
		printf 'Requires(postun): systemd\n'; \
		printf '\n%%description\n'; \
		printf 'Local DNS stub resolver supporting plaintext DNS, DoH, DoT, and DoQ.\n'; \
		printf '\n%%prep\n'; \
		printf '\n%%build\n'; \
		printf '\n%%install\n'; \
		printf 'rm -rf %%{buildroot}\n'; \
		printf 'mkdir -p %%{buildroot}\n'; \
		printf 'cp -a %s/. %%{buildroot}/\n' "$(abspath $(RPM_PAYLOAD_ROOT))"; \
		printf '\n%%pre\n'; \
		printf 'getent group %s >/dev/null 2>&1 || groupadd -r %s\n' "$(PREFIX)" "$(PREFIX)"; \
		printf 'id -u %s >/dev/null 2>&1 || useradd -r -g %s -s /usr/sbin/nologin -d /nonexistent -M %s\n' "$(PREFIX)" "$(PREFIX)" "$(PREFIX)"; \
		printf '\n%%post\n'; \
		printf 'config=/etc/%s/config.json\n' "$(PREFIX)"; \
		printf 'default_config=/usr/share/%s/config.default.json\n' "$(PREFIX)"; \
		printf 'if [ ! -f "$$config" ]; then install -m 0640 -o %s -g %s "$$default_config" "$$config"; fi\n' "$(PREFIX)" "$(PREFIX)"; \
		printf 'if command -v setcap >/dev/null 2>&1; then setcap '"'"'cap_net_bind_service=+ep'"'"' /usr/local/bin/%s || echo "warning: setcap failed; systemd capabilities are still configured" >&2; fi\n' "$(PREFIX)"; \
		printf 'systemctl daemon-reload >/dev/null 2>&1 || true\n'; \
		printf '\n%%preun\n'; \
		printf 'if [ "$$1" = "0" ]; then systemctl stop %s.service >/dev/null 2>&1 || true; fi\n' "$(PREFIX)"; \
		printf '\n%%postun\n'; \
		printf 'systemctl daemon-reload >/dev/null 2>&1 || true\n'; \
		printf 'if [ "$$1" = "0" ]; then userdel %s >/dev/null 2>&1 || true; groupdel %s >/dev/null 2>&1 || true; fi\n' "$(PREFIX)" "$(PREFIX)"; \
		printf '\n%%files\n'; \
		printf '%%license /usr/share/doc/%s/LICENSE\n' "$(PREFIX)"; \
		printf '%%dir /etc/%s\n' "$(PREFIX)"; \
		printf '%%config(noreplace) /etc/%s/config.example.json\n' "$(PREFIX)"; \
		printf '/usr/local/bin/%s\n' "$(PREFIX)"; \
		printf '/usr/share/%s/config.default.json\n' "$(PREFIX)"; \
		printf '/usr/lib/systemd/system/%s.service\n' "$(PREFIX)"; \
		printf '/etc/sysctl.d/80-%s.conf\n' "$(PREFIX)"; \
		printf '\n%%changelog\n'; \
		printf '* Tue Apr 28 2026 %s - %s-%s\n' "$(PKG_MAINTAINER)" "$(PKG_VERSION)" "$(PKG_RELEASE)"; \
		printf '%s\n' '- Automated package build.'; \
	} > "$@"

$(RPM_RPMRC):
	mkdir -p $(dir $@)
	{ \
		printf 'buildarch_compat: x86_64: aarch64 noarch\n'; \
		printf 'buildarch_compat: amd64: aarch64 noarch\n'; \
		printf 'buildarch_compat: aarch64: noarch\n'; \
	} > "$@"

$(RPM_LEGACY_RPMRC): $(RPM_RPMRC)
	mkdir -p $(dir $@)
	cp "$(RPM_RPMRC)" "$@"

$(RPM_FILE): $(RPM_PAYLOAD_ROOT) $(RPM_SPEC) $(RPM_RPMRC) $(RPM_LEGACY_RPMRC)
	@command -v rpmbuild >/dev/null 2>&1 || { echo "error: rpmbuild is required to build $(RPM_FILE)" >&2; exit 1; }
	mkdir -p $(DISTDIR) $(RPM_TOPDIR)/RPMS
	rm -f $@
	HOME="$(abspath $(RPM_HOME))" XDG_CONFIG_HOME="$(abspath $(RPM_XDG_CONFIG_HOME))" rpmbuild --define "_topdir $(abspath $(RPM_TOPDIR))" --define "_build_id_links none" --define "__strip /bin/true" --target "$(RPM_ARCH)" -bb "$(RPM_SPEC)"
	built_rpm=$$(find "$(RPM_TOPDIR)/RPMS" -type f -name '$(PREFIX)-$(PKG_VERSION)-*.rpm' | sort | tail -n 1); \
	test -n "$$built_rpm" || { echo "error: rpmbuild did not produce an RPM" >&2; exit 1; }; \
	cp "$$built_rpm" "$@"

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
