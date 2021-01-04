HOST_CC = cc
PKGCONFIG = pkg-config
LUA = lua

# using the pkg-config variable names for our install paths
INSTALL_LMOD = $(shell $(PKGCONFIG) --variable=INSTALL_LMOD $(LUA))
INSTALL_CMOD = $(shell $(PKGCONFIG) --variable=INSTALL_CMOD $(LUA))

CFLAGS  += $(shell $(PKGCONFIG) --cflags libsodium)
LDFLAGS += $(shell $(PKGCONFIG) --libs libsodium)

CFLAGS += -fPIC -Wall -Wextra -g -O2
CFLAGS += $(shell $(PKGCONFIG) --cflags $(LUA))

VERSION = $(shell $(LUA) aux/version.lua)

DLL=.so
LIB=.a

LUASODIUM_MODS := \
  crypto_auth \
  crypto_box \
  crypto_hash \
  crypto_onetimeauth \
  crypto_scalarmult \
  crypto_secretbox \
  crypto_sign \
  crypto_stream \
  crypto_verify \
  randombytes \
  utils \
  version

LUASODIUM_LUAS := \
  lua/luasodium.lua \
  $(addsuffix .lua,$(addprefix lua/luasodium/,$(LUASODIUM_MODS)))

LUASODIUM_CORES = $(foreach lib,$(LUASODIUM_MODS),$(addprefix $(lib)/,core ffi))
LUASODIUM_TESTS = $(addprefix test-,$(LUASODIUM_MODS))
LUASODIUM_TESTS_FFI = $(addprefix ffitest-,$(LUASODIUM_MODS))

LUASODIUM_OBJS = c/luasodium/core.o c/luasodium/ffi.o
LUASODIUM_OBJS += $(addsuffix .o,$(addprefix c/luasodium/,$(LUASODIUM_CORES)))

LUASODIUM_GCNO = $(LUASODIUM_OBJS:%.o=%.gcno)
LUASODIUM_GCDA = $(LUASODIUM_OBJS:%.o=%.gcda)

LUASODIUM_CORE_HEADERS = $(addsuffix /core.h,$(addprefix c/luasodium/,$(LUASODIUM_MODS)))
LUASODIUM_FFI_HEADERS = $(addsuffix /ffi.h,$(addprefix c/luasodium/,$(LUASODIUM_MODS)))
LUASODIUM_DLLS = $(LUASODIUM_OBJS:%.o=%$(DLL))
LUASODIUM_LIBS = $(LUASODIUM_OBJS:%.o=%$(LIB))

LUASODIUM_FFI_LOADER = c/luasodium/ffi-function-loader.h
LUASODIUM_FFI_IMPLEMENTATIONS = $(addsuffix /ffi-implementation.h,$(addprefix c/luasodium/,$(LUASODIUM_MODS)))

LUASODIUM_FFI_DEFAULT_SIG = c/luasodium/ffi-default-signatures.h
LUASODIUM_FFI_SIGNATURES  = $(addsuffix /ffi-signatures.h,$(addprefix c/luasodium/,$(LUASODIUM_MODS)))

INSTALL_LUAS = install-lua-luasodium $(addprefix install-lua-,$(LUASODIUM_MODS))
INSTALL_DLLS = install-dll-core install-dll-ffi $(addprefix install-dll-,$(LUASODIUM_MODS))
INSTALL_LIBS = install-lib-core install-lib-ffi $(addprefix install-lib-,$(LUASODIUM_MODS))

.PHONY: all clean release test github-release coverage install install-lua-luasodium $(INSTALL_LUAS) $(INSTALL_DLLS) $(INSTALL_LIBS)
.SUFFIXES:

all: $(LUASODIUM_DLLS) $(LUASODIUM_LIBS)

c/luasodium/ffi-function-loader.h: ffi/luasodium/_ffi/function_loader.lua | aux/bin2c
	./aux/bin2c $< $@ ffi_function_loader

c/luasodium/ffi-default-signatures.h: ffi/luasodium/_ffi/default_signatures.lua | aux/bin2c
	./aux/bin2c $< $@ ffi_default_signatures

c/luasodium/%/ffi-implementation.h: ffi/luasodium/%/implementation.lua | aux/bin2c
	./aux/bin2c $< $@ $(addsuffix _ffi_implementation,$(addprefix ls_,$(notdir $(patsubst %/,%,$(dir $<)))))

c/luasodium/%/ffi-signatures.h: ffi/luasodium/%/signatures.lua | aux/bin2c
	./aux/bin2c $< $@ $(addsuffix _ffi_signatures,$(addprefix ls_,$(notdir $(patsubst %/,%,$(dir $<)))))

c/luasodium/core.o: c/luasodium/core.c $(LUASODIUM_CORE_HEADERS) c/luasodium/version/ffi-implementation.h
	$(CC) $(CFLAGS) -o $@ -c $<

c/luasodium/ffi.o: c/luasodium/ffi.c $(LUASODIUM_FFI_HEADERS) $(LUASODIUM_FFI_LOADER) $(LUASODIUM_FFI_DEFAULT_SIG) $(LUASODIUM_FFI_SIGNATURES) $(LUASODIUM_FFI_IMPLEMENTATIONS)
	$(CC) $(CFLAGS) -o $@ -c $<

c/luasodium/version/core.o: c/luasodium/version/core.c c/luasodium/version/core.h c/luasodium/version/ffi-implementation.h
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

ffitest-%:
	busted --lua="$(shell which luajit)" --lpath 'ffi/?.lua' --verbose spec/$(@:ffitest-%=%)_spec.lua

test-%: c/luasodium/core$(DLL) c/luasodium/ffi$(DLL) c/luasodium/%/core$(DLL) c/luasodium/%/ffi$(DLL)
	busted --lua="$(shell which $(LUA))" --lpath 'lua/?.lua' --cpath 'c/?.so' --verbose spec/$(@:test-%=%)_spec.lua

ffitest:
	luajit -l aux.set_paths_ffi aux/verify-ffi.lua $(LUASODIUM_MODS)

test: $(LUASODIUM_TESTS) $(LUASODIUM_TESTS_FFI) ffitest

clean:
	rm -f $(LUASODIUM_DLLS)
	rm -f $(LUASODIUM_OBJS)
	rm -f $(LUASODIUM_LIBS)
	rm -f $(LUASODIUM_FFI_LOADER)
	rm -f $(LUASODIUM_FFI_IMPLEMENTATIONS)
	rm -f $(LUASODIUM_FFI_DEFAULT_SIG)
	rm -f $(LUASODIUM_FFI_SIGNATURES)
	rm -f $(LUASODIUM_GCDA)
	rm -f $(LUASODIUM_GCNO)

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

define LUA_INSTALL
install-lua-$(1):
	install -Dm0644 lua/luasodium/$(1).lua $(DESTDIR)$(INSTALL_LMOD)/luasodium/$(1).lua
endef

define DLL_INSTALL
install-dll-$(1): c/luasodium/$(1)/core$(DLL) c/luasodium/$(1)/ffi$(DLL)
	install -Dm0755 c/luasodium/$(1)/core$(DLL) $(DESTDIR)$(INSTALL_CMOD)/luasodium/$(1)/core$(DLL)
	install -Dm0755 c/luasodium/$(1)/ffi$(DLL) $(DESTDIR)$(INSTALL_CMOD)/luasodium/$(1)/ffi$(DLL)
endef

define LIB_INSTALL
install-lib-$(1): c/luasodium/$(1)/core$(LIB) c/luasodium/$(1)/ffi$(LIB)
	install -Dm0644 c/luasodium/$(1)/core$(LIB) $(DESTDIR)$(INSTALL_CMOD)/luasodium/$(1)/core$(LIB)
	install -Dm0644 c/luasodium/$(1)/ffi$(LIB) $(DESTDIR)$(INSTALL_CMOD)/luasodium/$(1)/ffi$(LIB)
endef

install-lib-core: c/luasodium/core$(LIB)
	install -Dm0644 c/luasodium/core$(LIB) $(DESTDIR)$(INSTALL_CMOD)/luasodium/core$(LIB)

install-lib-ffi: c/luasodium/ffi$(LIB)
	install -Dm0644 c/luasodium/ffi$(LIB) $(DESTDIR)$(INSTALL_CMOD)/luasodium/ffi$(LIB)

install-dll-core: c/luasodium/core$(DLL)
	install -Dm0755 c/luasodium/core$(DLL) $(DESTDIR)$(INSTALL_CMOD)/luasodium/core$(DLL)

install-dll-ffi: c/luasodium/ffi$(DLL)
	install -Dm0755 c/luasodium/ffi$(DLL) $(DESTDIR)$(INSTALL_CMOD)/luasodium/ffi$(DLL)

install-lua-luasodium:
	install -Dm0644 lua/luasodium.lua $(DESTDIR)$(INSTALL_LMOD)/luasodium.lua

$(foreach mod,$(LUASODIUM_MODS),$(eval $(call LUA_INSTALL,$(mod))))
$(foreach mod,$(LUASODIUM_MODS),$(eval $(call DLL_INSTALL,$(mod))))
$(foreach mod,$(LUASODIUM_MODS),$(eval $(call LIB_INSTALL,$(mod))))

install-luas: $(INSTALL_LUAS)

install-dlls: $(INSTALL_DLLS)

install-libs: $(INSTALL_LIBS)

install: install-luas install-dlls install-libs

coverage:
	$(MAKE) -f Makefile clean
	$(MAKE) -f Makefile LDFLAGS="--coverage $(shell $(PKGCONFIG) --libs libsodium)" CFLAGS="-fPIC -Wall -Wextra -g -O0 -fprofile-arcs -ftest-coverage --coverage $(shell $(PKGCONFIG) --cflags $(LUA)) $(shell $(PKGCONFIG) --libs libsodium)" LUA=$(LUA)
	busted --lua="$(shell which $(LUA))" --lpath 'lua/?.lua' --cpath 'c/?.so' --verbose
	gcovr -r . --html-details -o coverage.html

coverage-jit:
	$(MAKE) -f Makefile coverage LUA=luajit

# for some reason, running busted with ffi path + luajit + spec test folder gives an error
# but running an individual spec doesn't

define FFI_COVERAGE
coverage-ffi-$(1):
	busted --lua="$(shell which luajit)" --lpath 'ffi/?.lua' --verbose spec/$(1)_spec.lua
endef
$(foreach mod,$(LUASODIUM_MODS),$(eval $(call FFI_COVERAGE,$(mod))))

FFI_COVERAGES = $(addprefix coverage-ffi-,$(LUASODIUM_MODS))

coverage-ffi: $(FFI_COVERAGES)
