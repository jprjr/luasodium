.PHONY: release

HOST_CC = cc

include Makefile.dist

LUASODIUM_FFIS = \
  luasodium.luah \
  luasodium/crypto_secretbox.luah \
  luasodium/randombytes.luah

%.luah: %-ffi.lua aux/bin2c
	./aux/bin2c $< $@ $(patsubst %.luah,%_ffi,$(notdir $@))

aux/bin2c: aux/bin2c.c
	$(HOST_CC) -o $@ $^

clean:
	$(MAKE) -f Makefile.dist clean
	rm -f aux/bin2c $(LUASODIUM_FFIS)

VERSION = $(shell $(LUA) aux/version.lua)

release: $(LUASODIUM_DLLS) $(LUASODIUM_FFIS)
	rm -f luasodium-$(VERSION).tar.gz
	rm -f luasodium-$(VERSION).tar.xz
	mkdir -p luasodium-$(VERSION)
	mkdir -p luasodium-$(VERSION)/luasodium
	cp luasodium.c luasodium-$(VERSION)/luasodium.c
	cp luasodium/randombytes.c luasodium-$(VERSION)/luasodium/randombytes.c
	cp luasodium/crypto_secretbox.c luasodium-$(VERSION)/luasodium/crypto_secretbox.c
	cp luasodium-ffi.lua luasodium-$(VERSION)/luasodium-ffi.lua
	cp luasodium/randombytes-ffi.lua luasodium-$(VERSION)/luasodium/randombytes-ffi.lua
	cp luasodium/crypto_secretbox-ffi.lua luasodium-$(VERSION)/luasodium/crypto_secretbox-ffi.lua
	cp luasodium.luah luasodium-$(VERSION)/luasodium.luah
	cp luasodium/randombytes.luah luasodium-$(VERSION)/luasodium/randombytes.luah
	cp luasodium/crypto_secretbox.luah luasodium-$(VERSION)/luasodium/crypto_secretbox.luah
	cp README.md luasodium-$(VERSION)/README.md
	cp LICENSE luasodium-$(VERSION)/LICENSE
	cp Makefile.dist luasodium-$(VERSION)/Makefile
	sed 's/@VERSION@/$(VERSION)/g' < specs/luasodium-release-template.rockspec > luasodium-$(VERSION)/luasodium-$(VERSION)-1.rockspec
	tar cvf luasodium-$(VERSION).tar luasodium-$(VERSION)
	gzip -k luasodium-$(VERSION).tar
	xz luasodium-$(VERSION).tar
	rm -rf luasodium-$(VERSION)
