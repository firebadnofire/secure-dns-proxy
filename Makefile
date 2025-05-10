# Makefile for packaging secure-dns-proxy as a tarball
# -----------------------------------------------------

# metadata
PREFIX      := secure-dns-proxy
VERSION     := $(shell git describe --tags --always 2>/dev/null || echo "dev")
DISTDIR     := dist
STAGEDIR    := build/stage

# staging subdirs
BIN_STG     := $(STAGEDIR)/$(PREFIX)/bin
CONF_STG    := $(STAGEDIR)/$(PREFIX)/etc/$(PREFIX)

# source config
EXAMPLE_CONF := upstreams-example.conf

.PHONY: all clean stage package

all: package

# 1) stage the binary
$(BIN_STG):
	mkdir -p $@
	# build directly into staging
	go build -o $(BIN_STG)/$(PREFIX) .

# 2) stage the config
$(CONF_STG):
	mkdir -p $@
	cp $(EXAMPLE_CONF) $(CONF_STG)/upstreams.conf

# 3) assemble the staging tree
stage: $(BIN_STG) $(CONF_STG)

# 4) create the final tar.gz
#    it will contain a top-level folder named "secure-dns-proxy"
$(DISTDIR)/$(PREFIX)-$(VERSION).tar.gz: stage
	mkdir -p $(DISTDIR)
	tar -czf $@ \
	  -C $(STAGEDIR) $(PREFIX)

package: $(DISTDIR)/$(PREFIX)-$(VERSION).tar.gz

# cleanup everything
clean:
	rm -rf build $(DISTDIR)

