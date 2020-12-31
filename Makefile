.PHONY: release

HOST_CC = cc

include Makefile.dist

LUASODIUM_FFIS = \
  c/luasodium/utils/core.luah \
  c/luasodium/version/core.luah \
  c/luasodium/crypto_secretbox/core.luah \
  c/luasodium/crypto_box/core.luah \
  c/luasodium/crypto_auth/core.luah \
  c/luasodium/crypto_scalarmult/core.luah \
  c/luasodium/randombytes/core.luah

c/luasodium/version/core.luah: ffi/luasodium/version.lua aux/bin2c
	./aux/bin2c $< $@ $(patsubst %.lua,%_lua,$(notdir $<))

c/luasodium/utils/core.luah: ffi/luasodium/utils.lua aux/bin2c
	./aux/bin2c $< $@ $(patsubst %.lua,%_lua,$(notdir $<))

c/luasodium/crypto_secretbox/core.luah: ffi/luasodium/crypto_secretbox.lua aux/bin2c
	./aux/bin2c $< $@ $(patsubst %.lua,%_lua,$(notdir $<))

c/luasodium/crypto_scalarmult/core.luah: ffi/luasodium/crypto_scalarmult.lua aux/bin2c
	./aux/bin2c $< $@ $(patsubst %.lua,%_lua,$(notdir $<))

c/luasodium/crypto_box/core.luah: ffi/luasodium/crypto_box.lua aux/bin2c
	./aux/bin2c $< $@ $(patsubst %.lua,%_lua,$(notdir $<))

c/luasodium/crypto_auth/core.luah: ffi/luasodium/crypto_auth.lua aux/bin2c
	./aux/bin2c $< $@ $(patsubst %.lua,%_lua,$(notdir $<))

c/luasodium/randombytes/core.luah: ffi/luasodium/randombytes.lua aux/bin2c
	./aux/bin2c $< $@ $(patsubst %.lua,%_lua,$(notdir $<))

aux/bin2c: aux/bin2c.c
	$(HOST_CC) -o $@ $^

clean:
	$(MAKE) -f Makefile.dist clean
	rm -f aux/bin2c $(LUASODIUM_FFIS)

README.md: docs/parts.txt $(wildcard docs/*.md)
	while read line ; do cat docs/$$line ; done < docs/parts.txt > README.md

VERSION = $(shell $(LUA) aux/version.lua)

release: $(LUASODIUM_FFIS) README.md
	rm -rf luasodium-$(VERSION) dist/luasodium-$(VERSION)
	rm -rf dist/luasodium-$(VERSION).tar.gz
	rm -rf dist/luasodium-$(VERSION).tar.xz
	rm -f $(LUASODIUM_OBJS) $(LUASODIUM_DLLS)
	mkdir -p dist
	mkdir -p luasodium-$(VERSION)
	cp -r c luasodium-$(VERSION)/
	cp -r lua luasodium-$(VERSION)/
	cp -r ffi luasodium-$(VERSION)/
	cp README.md luasodium-$(VERSION)/README.md
	cp LICENSE luasodium-$(VERSION)/LICENSE
	cp Makefile.dist luasodium-$(VERSION)/Makefile
	cp dist.ini luasodium-$(VERSION)/dist.ini
	sed 's/@VERSION@/$(VERSION)/g' < specs/luasodium-release-template.rockspec > luasodium-$(VERSION)/luasodium-$(VERSION)-1.rockspec
	tar cvf dist/luasodium-$(VERSION).tar luasodium-$(VERSION)
	gzip -k dist/luasodium-$(VERSION).tar
	xz dist/luasodium-$(VERSION).tar
	mv luasodium-$(VERSION) dist/luasodium-$(VERSION)
