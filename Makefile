.PHONY: all clean release test github-release
.SUFFIXES:

HOST_CC = cc
PKGCONFIG = pkg-config
LUA = lua

VERSION = $(shell $(LUA) aux/version.lua)

DLL=.so
LIB=.a

LUASODIUM_MODS := \
  version \
  utils \
  crypto_secretbox \
  crypto_sign \
  crypto_auth \
  crypto_hash \
  crypto_box \
  crypto_scalarmult \
  randombytes

LUASODIUM_LUAS := \
  luasodium.lua \
  $(addsuffix .lua,$(addprefix luasodium/,$(LUASODIUM_MODS)))

LUASODIUM_CORES = $(foreach lib,$(LUASODIUM_MODS),$(addprefix $(lib)/,core ffi))
LUASODIUM_TESTS = $(addprefix test-,$(LUASODIUM_MODS))

LUASODIUM_OBJS = c/luasodium/core.o c/luasodium/ffi.o
LUASODIUM_OBJS += $(addsuffix .o,$(addprefix c/luasodium/,$(LUASODIUM_CORES)))

LUASODIUM_CORE_HEADERS = $(addsuffix /core.h,$(addprefix c/luasodium/,$(LUASODIUM_MODS)))
LUASODIUM_FFI_HEADERS = $(addsuffix /ffi.h,$(addprefix c/luasodium/,$(LUASODIUM_MODS)))
LUASODIUM_DLLS = $(LUASODIUM_OBJS:%.o=%$(DLL))
LUASODIUM_LIBS = $(LUASODIUM_OBJS:%.o=%$(LIB))

LUASODIUM_FFI_LOADER = c/luasodium/ffi-function-loader.h
LUASODIUM_FFI_IMPLEMENTATIONS = $(addsuffix /ffi-implementation.h,$(addprefix c/luasodium/,$(LUASODIUM_MODS)))

LUASODIUM_FFI_DEFAULT_SIG = c/luasodium/ffi-default-signatures.h
LUASODIUM_FFI_SIGNATURES  = $(addsuffix /ffi-signatures.h,$(addprefix c/luasodium/,$(LUASODIUM_MODS)))

CFLAGS  += $(shell $(PKGCONFIG) --cflags libsodium)
LDFLAGS += $(shell $(PKGCONFIG) --libs libsodium)

CFLAGS += -fPIC -Wall -Wextra -g -O2
CFLAGS += $(shell $(PKGCONFIG) --cflags $(LUA))

all: $(LUASODIUM_DLLS) $(LUASODIUM_LIBS)

c/luasodium/ffi-function-loader.h: ffi/luasodium/_ffi/function_loader.lua aux/bin2c
	./aux/bin2c $< $@ ffi_function_loader

c/luasodium/ffi-default-signatures.h: ffi/luasodium/_ffi/default_signatures.lua aux/bin2c
	./aux/bin2c $< $@ ffi_default_signatures

c/luasodium/%/ffi-implementation.h: ffi/luasodium/%/implementation.lua aux/bin2c
	./aux/bin2c $< $@ $(addsuffix _ffi_implementation,$(addprefix ls_,$(notdir $(patsubst %/,%,$(dir $<)))))

c/luasodium/%/ffi-signatures.h: ffi/luasodium/%/signatures.lua aux/bin2c
	./aux/bin2c $< $@ $(addsuffix _ffi_signatures,$(addprefix ls_,$(notdir $(patsubst %/,%,$(dir $<)))))

c/luasodium/core.o: c/luasodium/core.c $(LUASODIUM_CORE_HEADERS) c/luasodium/version/ffi-implementation.h
	$(CC) $(CFLAGS) -o $@ -c $<

c/luasodium/ffi.o: c/luasodium/ffi.c $(LUASODIUM_FFI_HEADERS) $(LUASODIUM_FFI_LOADER) $(LUASODIUM_FFI_DEFAULT_SIG) $(LUASODIUM_FFI_SIGNATURES) $(LUASODIUM_FFI_IMPLEMENTATIONS)
	$(CC) $(CFLAGS) -o $@ -c $<

c/luasodium/version/core.o: c/luasodium/version/core.c c/luasodium/version/core.h c/luasodium/version/ffi-implementation.h
	$(CC) $(CFLAGS) -o $@ -c $<

c/luasodium/version/ffi.o: c/luasodium/version/ffi.c c/luasodium/version/core.h c/luasodium/version/ffi-implementation.h
	$(CC) $(CFLAGS) -o $@ -c $<

%/core.o: %/core.c %/core.h %/constants.h
	$(CC) $(CFLAGS) -o $@ -c $<

%/ffi.o: %/ffi.c %/ffi.h %/constants.h %/ffi-implementation.h %/ffi-signatures.h $(LUASODIUM_FFI_LOADER) $(LUASODIUM_FFI_DEFAULT_SIG)
	$(CC) $(CFLAGS) -o $@ -c $<

%$(DLL): %.o
	$(CC) -shared -o $@ $< $(LDFLAGS)

%$(LIB): %.o
	ar rcs $@ $^

aux/bin2c: aux/bin2c.c
	$(HOST_CC) -o $@ $^

test-jit:
	cd ffi && luajit ../test-crypto_auth.lua
	cd ffi && luajit ../test-crypto_box.lua
	cd ffi && luajit ../test-crypto_hash.lua
	cd ffi && luajit ../test-crypto_scalarmult.lua
	cd ffi && luajit ../test-crypto_secretbox.lua
	cd ffi && luajit ../test-crypto_sign.lua
	cd ffi && luajit ../test-randombytes.lua
	cd ffi && luajit ../test-utils.lua

test-%: c/luasodium/%/core$(DLL) c/luasodium/%/ffi$(DLL)
	$(LUA) -l aux.set_paths $@.lua

test: $(LUASODIUM_TESTS)

clean:
	rm -f $(LUASODIUM_DLLS)
	rm -f $(LUASODIUM_OBJS)
	rm -f $(LUASODIUM_LIBS)
	rm -f $(LUASODIUM_FFI_LOADER)
	rm -f $(LUASODIUM_FFI_IMPLEMENTATIONS)
	rm -f $(LUASODIUM_FFI_DEFAULT_SIG)
	rm -f $(LUASODIUM_FFI_SIGNATURES)

release: $(LUASODIUM_FFI_IMPLEMENTATIONS) $(LUASODIUM_FFI_SIGNATURES) README.md c/luasodium/ffi-function-loader.h c/luasodium/ffi-default-signatures.h
	rm -rf luasodium-$(VERSION) dist/luasodium-$(VERSION)
	rm -rf dist/luasodium-$(VERSION).tar.gz
	rm -rf dist/luasodium-$(VERSION).tar.xz
	rm -f $(LUASODIUM_OBJS) $(LUASODIUM_DLLS) $(LUASODIUM_LIBS) aux/bin2c
	mkdir -p dist
	mkdir -p luasodium-$(VERSION)/
	rsync -a aux luasodium-$(VERSION)/
	rsync -a c luasodium-$(VERSION)/
	rsync -a lua luasodium-$(VERSION)/
	rsync -a ffi luasodium-$(VERSION)/
	rsync -a rockspecs luasodium-$(VERSION)/
	perl aux/amalgate.pl c/luasodium/core.c > luasodium-$(VERSION)/c/luasodium-amalgamated-core.c
	perl aux/amalgate.pl c/luasodium/ffi.c > luasodium-$(VERSION)/c/luasodium-amalgamated-ffi.c
	rsync -a README.md luasodium-$(VERSION)/README.md
	rsync -a LICENSE luasodium-$(VERSION)/LICENSE
	rsync -a Makefile luasodium-$(VERSION)/Makefile
	rsync -a dist.ini luasodium-$(VERSION)/dist.ini
	rsync -a test-*.lua luasodium-$(VERSION)/
	sed 's/@VERSION@/$(VERSION)/g' < rockspecs/luasodium-release-template.rockspec > luasodium-$(VERSION)/rockspecs/luasodium-$(VERSION)-1.rockspec
	sed 's/@VERSION@/$(VERSION)/g' < dist.ini > luasodium-$(VERSION)/dist.ini
	tar cvf dist/luasodium-$(VERSION).tar luasodium-$(VERSION)
	gzip -k dist/luasodium-$(VERSION).tar
	xz dist/luasodium-$(VERSION).tar
	mv luasodium-$(VERSION) dist/luasodium-$(VERSION)

github-release:
	source $(HOME)/.github-token && github-release release \
	  --user jprjr \
	  --repo luasodium \
	  --tag v$(VERSION)
	source $(HOME)/.github-token && github-release upload \
	  --user jprjr \
	  --repo luasodium \
	  --tag v$(VERSION) \
	  --name luasodium-$(VERSION).tar.gz \
	  --file dist/luasodium-$(VERSION).tar.gz
	source $(HOME)/.github-token && github-release upload \
	  --user jprjr \
	  --repo luasodium \
	  --tag v$(VERSION) \
	  --name luasodium-$(VERSION).tar.xz \
	  --file dist/luasodium-$(VERSION).tar.xz

