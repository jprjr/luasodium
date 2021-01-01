.PHONY: release directories test hmm

HOST_CC = cc

LUASODIUM_LUAS = \
  luasodium.lua \
  luasodium/core.lua \
  luasodium/ffi.lua \
  $(addsuffix,.lua,$(addprefix luasodium/,$(LUASODIUM_MODS)))

include Makefile.dist

$(shell mkdir -p $(LUASODIUM_LIB_DIRS) luasodium)
$(shell cp ffi/luasodium.lua luasodium.lua)

LUASODIUM_LOCAL_DLLS = $(LUASODIUM_DLLS:c/%=%)
LUASODIUM_LOCAL_LIBS = $(LUASODIUM_LIBS:c/%=%)

test: $(LUASODIUM_LUAS) $(LUASODIUM_DLLS) $(LUASODIUM_LIBS) $(LUASODIUM_LOCAL_DLLS) $(LUASODIUM_LOCAL_LIBS)
	$(LUA) test-crypto_auth.lua
	$(LUA) test-crypto_box.lua
	$(LUA) test-crypto_scalarmult.lua
	$(LUA) test-crypto_secretbox.lua
	$(LUA) test-crypto_sign.lua
	$(LUA) test-randombytes.lua
	$(LUA) test-utils.lua

luasodium/%.lua: lua/luasodium/%.lua $(basename $@)
	cp $< $@

LUASODIUM_FFIS = $(addsuffix /core.luah,$(addprefix c/luasodium/,$(LUASODIUM_MODS)))

hmm:
	echo $(LUASODIUM_FFIS)

luasodium/%$(DLL): c/luasodium/%$(DLL)
	cp $< $@

luasodium/%$(LIB): c/luasodium/%$(LIB)
	cp $< $@

c/luasodium/%/core.luah: ffi/luasodium/%.lua aux/bin2c
	./aux/bin2c $< $@ $(patsubst %.lua,%_lua,$(notdir $<))

aux/bin2c: aux/bin2c.c
	$(HOST_CC) -o $@ $^

clean:
	$(MAKE) -f Makefile.dist clean
	rm -f aux/bin2c $(LUASODIUM_FFIS)
	rm -f $(LUASODIUM_LOCAL_DLLS)
	rm -f $(LUASODIUM_LOCAL_LIBS)

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
