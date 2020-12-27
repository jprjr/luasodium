.PHONY: release

HOST_CC = cc

include Makefile.dist

LUASODIUM_FFIS = \
  c/luasodium.luah \
  c/luasodium/crypto_secretbox.luah \
  c/luasodium/crypto_box.luah \
  c/luasodium/randombytes.luah \
  c/luasodium/version.luah

c/%.luah: lua/%.lua aux/bin2c
	./aux/bin2c $< $@ $(patsubst %.lua,%_lua,$(notdir $<))

aux/bin2c: aux/bin2c.c
	$(HOST_CC) -o $@ $^

clean:
	$(MAKE) -f Makefile.dist clean
	rm -f aux/bin2c $(LUASODIUM_FFIS)

VERSION = $(shell $(LUA) aux/version.lua)

release: $(LUASODIUM_DLLS) $(LUASODIUM_FFIS)
	rm -rf luasodium-$(VERSION) dist/luasodium-$(VERSION)
	rm -rf dist/luasodium-$(VERSION).tar.gz
	rm -rf dist/luasodium-$(VERSION).tar.xz
	mkdir -p dist
	mkdir -p luasodium-$(VERSION)
	mkdir -p luasodium-$(VERSION)/c/luasodium
	mkdir -p luasodium-$(VERSION)/lua/luasodium
	cp c/luasodium.h luasodium-$(VERSION)/c/luasodium.h
	cp c/luasodium.c luasodium-$(VERSION)/c/luasodium.c
	cp c/luasodium/randombytes.c luasodium-$(VERSION)/c/luasodium/randombytes.c
	cp c/luasodium/crypto_secretbox.c luasodium-$(VERSION)/c/luasodium/crypto_secretbox.c
	cp c/luasodium/crypto_box.c luasodium-$(VERSION)/c/luasodium/crypto_secretbox.c
	cp lua/luasodium.lua luasodium-$(VERSION)/lua/luasodium.lua
	cp lua/luasodium/version.lua luasodium-$(VERSION)/lua/luasodium/version.lua
	cp lua/luasodium/randombytes.lua luasodium-$(VERSION)/lua/luasodium/randombytes.lua
	cp lua/luasodium/crypto_secretbox.lua luasodium-$(VERSION)/lua/luasodium/crypto_secretbox.lua
	cp lua/luasodium/crypto_box.lua luasodium-$(VERSION)/lua/luasodium/crypto_secretbox.lua
	cp c/luasodium.luah luasodium-$(VERSION)/c/luasodium.luah
	cp c/luasodium/version.luah luasodium-$(VERSION)/c/luasodium/version.luah
	cp c/luasodium/randombytes.luah luasodium-$(VERSION)/c/luasodium/randombytes.luah
	cp c/luasodium/crypto_secretbox.luah luasodium-$(VERSION)/c/luasodium/crypto_secretbox.luah
	cp c/luasodium/crypto_box.luah luasodium-$(VERSION)/c/luasodium/crypto_secretbox.luah
	cp README.md luasodium-$(VERSION)/README.md
	cp LICENSE luasodium-$(VERSION)/LICENSE
	cp Makefile.dist luasodium-$(VERSION)/Makefile
	cp dist.ini luasodium-$(VERSION)/dist.ini
	sed 's/@VERSION@/$(VERSION)/g' < specs/luasodium-release-template.rockspec > luasodium-$(VERSION)/luasodium-$(VERSION)-1.rockspec
	tar cvf dist/luasodium-$(VERSION).tar luasodium-$(VERSION)
	gzip -k dist/luasodium-$(VERSION).tar
	xz dist/luasodium-$(VERSION).tar
	mv luasodium-$(VERSION) dist/luasodium-$(VERSION)
