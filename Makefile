.PHONY: all clean release directories test test-jit
.SUFFIXES:

HOST_CC = cc
PKGCONFIG = pkg-config
LUA = lua

DLL=.so
LIB=.a

CFLAGS  += $(shell $(PKGCONFIG) --cflags libsodium)
LDFLAGS += $(shell $(PKGCONFIG) --libs libsodium)

CFLAGS += -fPIC -Wall -Wextra -g -O2
CFLAGS += $(shell $(PKGCONFIG) --cflags $(LUA))

LUASODIUM_MODS := \
  version \
  utils \
  crypto_secretbox \
  crypto_sign \
  crypto_auth \
  crypto_box \
  crypto_scalarmult \
  randombytes

LUASODIUM_LUAS := \
  luasodium.lua \
  $(addsuffix .lua,$(addprefix luasodium/,$(LUASODIUM_MODS)))

LUASODIUM_CORES = $(foreach lib,$(LUASODIUM_MODS),$(addprefix $(lib)/,core ffi))

LUASODIUM_LIB_DIRS = $(foreach lib,$(LUASODIUM_MODS),$(addprefix luasodium/,$(lib)))

LUASODIUM_OBJS = $(addsuffix .o,$(addprefix c/luasodium/,$(LUASODIUM_CORES)))

LUASODIUM_DLLS = $(addsuffix $(DLL),$(addprefix c/luasodium/,$(LUASODIUM_CORES)))
LUASODIUM_LIBS = $(addsuffix $(LIB),$(addprefix c/luasodium/,$(LUASODIUM_CORES)))

LUASODIUM_FFI_IMPLEMENTATIONS = $(addsuffix /ffi-implementation.h,$(addprefix c/luasodium/,$(LUASODIUM_MODS)))
LUASODIUM_FFI_SIGNATURES = $(addsuffix /ffi-signatures.h,$(addprefix c/luasodium/,$(LUASODIUM_MODS)))

$(shell mkdir -p $(LUASODIUM_LIB_DIRS) luasodium)
$(shell cp lua/luasodium.lua luasodium.lua)

LUASODIUM_LOCAL_DLLS = $(LUASODIUM_DLLS:c/%=%) luasodium/core$(DLL) luasodium/ffi$(DLL)
LUASODIUM_LOCAL_LIBS = $(LUASODIUM_LIBS:c/%=%) luasodium/core$(LIB) luasodium/ffi$(LIB)

LUASODIUM_TESTS = $(addprefix test-,$(LUASODIUM_MODS))
LUASODIUM_STATICS = $(addsuffix .luastatic.c,$(LUASODIUM_TESTS))

all: $(LUASODIUM_DLLS) $(LUASODIUM_LIBS)

c/luasodium/%$(DLL): c/luasodium/%.o
	$(CC) -shared -o $@ $< $(LDFLAGS)

c/luasodium/%$(LIB): c/luasodium/%.o
	ar rcs $@ $<

c/luasodium/core.o: c/luasodium/core.c
	$(CC) $(CFLAGS) -o $@ -c $<

c/luasodium/ffi.o: c/luasodium/ffi.c $(LUASODIUM_FFI_IMPLEMENTATIONS) $(LUASODIUM_FFI_SIGNATURES) c/luasodium/ffi-function-loader.h c/luasodium/ffi-default-signatures.h
	$(CC) $(CFLAGS) -o $@ -c $<

c/luasodium/version/core.o: c/luasodium/version/core.c c/luasodium/version/core.h c/luasodium/version/ffi-implementation.h
	$(CC) $(CFLAGS) -o $@ -c $<

c/luasodium/version/ffi.o: c/luasodium/version/ffi.c c/luasodium/version/core.h c/luasodium/version/ffi-implementation.h
	$(CC) $(CFLAGS) -o $@ -c $<

%/core.o: %/core.c %/constants.h
	$(CC) $(CFLAGS) -o $@ -c $<

%/ffi.o: %/ffi.c %/ffi.h %/constants.h %/ffi-implementation.h %/ffi-signatures.h c/luasodium/ffi-function-loader.h c/luasodium/ffi-default-signatures.h
	$(CC) $(CFLAGS) -o $@ -c $<

test-%: test-%.lua luasodium/%.lua luasodium/%/ffi.a luasodium/%/core.a
	luastatic test-$(@:test-%=%).lua luasodium/$(@:test-%=%).lua /opt/luajit-2.1.0/lib/libluajit-5.1.a luasodium/$(@:test-%=%)/ffi.a luasodium/$(@:test-%=%)/core.a /usr/lib/libsodium.a -I/opt/luajit-2.1.0/include/luajit-2.1

luasodium/%.lua: lua/luasodium/%.lua $(basename $@)
	cp $< $@

luasodium/%$(DLL): c/luasodium/%$(DLL)
	cp $< $@

luasodium/%$(LIB): c/luasodium/%$(LIB)
	cp $< $@

c/luasodium/ffi-function-loader.h: ffi/luasodium/_ffi/function_loader.lua aux/bin2c
	./aux/bin2c $< $@ ffi_function_loader

c/luasodium/ffi-default-signatures.h: ffi/luasodium/_ffi/default_signatures.lua aux/bin2c
	./aux/bin2c $< $@ ffi_default_signatures

c/luasodium/%/ffi-implementation.h: ffi/luasodium/%/implementation.lua aux/bin2c
	./aux/bin2c $< $@ $(addsuffix _ffi_implementation,$(addprefix ls_,$(notdir $(patsubst %/,%,$(dir $<)))))

c/luasodium/%/ffi-signatures.h: ffi/luasodium/%/signatures.lua aux/bin2c
	./aux/bin2c $< $@ $(addsuffix _ffi_signatures,$(addprefix ls_,$(notdir $(patsubst %/,%,$(dir $<)))))

aux/bin2c: aux/bin2c.c
	$(HOST_CC) -o $@ $^

clean:
	rm -f $(LUASODIUM_DLLS) $(LUASODIUM_OBJS) $(LUASODIUM_LIBS)
	rm -f aux/bin2c $(LUASODIUM_FFI_IMPLEMENTATIONS) c/luasodium/ffi-function-loader.h c/luasodium/ffi-default-signatures.h
	rm -f $(LUASODIUM_LOCAL_DLLS)
	rm -f $(LUASODIUM_LOCAL_LIBS)
	rm -f $(LUASODIUM_STATICS)
	rm -f $(LUASODIUM_TESTS)
	rm -f $(LUASODIUM_LUAS)

VERSION = $(shell $(LUA) aux/version.lua)

test: $(LUASODIUM_LOCAL_DLLS) $(LUASODIUM_LOCAL_LIBS)
	$(LUA) test-crypto_auth.lua
	$(LUA) test-crypto_box.lua
	$(LUA) test-crypto_scalarmult.lua
	$(LUA) test-crypto_secretbox.lua
	$(LUA) test-crypto_sign.lua
	$(LUA) test-randombytes.lua
	$(LUA) test-utils.lua

test-jit:
	cd ffi && luajit ../test-crypto_auth.lua
	cd ffi && luajit ../test-crypto_box.lua
	cd ffi && luajit ../test-crypto_scalarmult.lua
	cd ffi && luajit ../test-crypto_secretbox.lua
	cd ffi && luajit ../test-crypto_sign.lua
	cd ffi && luajit ../test-randombytes.lua
	cd ffi && luajit ../test-utils.lua

release: $(LUASODIUM_FFI_IMPLEMENTATIONS) $(LUASODIUM_FFI_IMPLEMENTATIONS) README.md c/luasodium/ffi-function-loader.h c/luasodium/ffi-default-signatures.h
	rm -rf luasodium-$(VERSION) dist/luasodium-$(VERSION)
	rm -rf dist/luasodium-$(VERSION).tar.gz
	rm -rf dist/luasodium-$(VERSION).tar.xz
	rm -f $(LUASODIUM_OBJS) $(LUASODIUM_DLLS) $(LUASODIUM_LIBS)
	mkdir -p dist
	mkdir -p luasodium-$(VERSION)/c/luasodium
	mkdir -p luasodium-$(VERSION)/lua
	perl aux/amalgate.pl c/luasodium/core.c > luasodium-$(VERSION)/c/luasodium/core.c
	perl aux/amalgate.pl c/luasodium/ffi.c > luasodium-$(VERSION)/c/luasodium/ffi.c
	cp lua/luasodium.lua luasodium-$(VERSION)/lua/luasodium.lua
	cp -r ffi luasodium-$(VERSION)/
	cp README.md luasodium-$(VERSION)/README.md
	cp LICENSE luasodium-$(VERSION)/LICENSE
	cp Makefile.dist luasodium-$(VERSION)/Makefile
	cp dist.ini luasodium-$(VERSION)/dist.ini
	sed 's/@VERSION@/$(VERSION)/g' < rockspecs/luasodium-release-template.rockspec > luasodium-$(VERSION)/luasodium-$(VERSION)-1.rockspec
	tar cvf dist/luasodium-$(VERSION).tar luasodium-$(VERSION)
	gzip -k dist/luasodium-$(VERSION).tar
	xz dist/luasodium-$(VERSION).tar
	mv luasodium-$(VERSION) dist/luasodium-$(VERSION)
