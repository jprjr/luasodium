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

VERSION = $(shell git describe --tags --abbrev=0)
VERSION_NUM   = $(subst v,,$(VERSION))
VERSION_PARTS = $(subst ., ,$(VERSION_NUM))
VERSION_MAJOR = $(word 1,$(VERSION_PARTS))
VERSION_MINOR = $(word 2,$(VERSION_PARTS))
VERSION_PATCH = $(word 3,$(VERSION_PARTS))

DLL=.so
LIB=.a

LUASODIUM_MODS := \
  crypto_aead \
  crypto_auth \
  crypto_box \
  crypto_generichash \
  crypto_hash \
  crypto_onetimeauth \
  crypto_pwhash \
  crypto_scalarmult \
  crypto_secretbox \
  crypto_secretstream \
  crypto_shorthash \
  crypto_sign \
  crypto_stream \
  crypto_verify \
  randombytes \
  utils \
  version

LUASODIUM_LUAS := \
  lua/luasodium/version/implementation.lua

LUASODIUM_CORES = $(foreach lib,$(LUASODIUM_MODS),$(addprefix $(lib)/,core ffi))
LUASODIUM_TESTS = $(addprefix test-,$(LUASODIUM_MODS))

LUASODIUM_OBJS = c/luasodium/luasodium.o $(addsuffix .o,$(addprefix c/luasodium/,$(LUASODIUM_CORES)))

LUASODIUM_GCNO = $(LUASODIUM_OBJS:%.o=%.gcno)
LUASODIUM_GCDA = $(LUASODIUM_OBJS:%.o=%.gcda)

LUASODIUM_DLLS = c/luasodium$(DLL)
LUASODIUM_LIBS = c/luasodium$(LIB)

INSTALL_LUAS = install-lua-luasodium $(addprefix install-lua-,$(LUASODIUM_MODS))
INSTALL_DLLS = install-dll-core install-dll-ffi $(addprefix install-dll-,$(LUASODIUM_MODS))
INSTALL_LIBS = install-lib-core install-lib-ffi $(addprefix install-lib-,$(LUASODIUM_MODS))

VERSION_FILES = cmake/modules/LuasodiumVersion.cmake c/luasodium/version/constants.h lua/luasodium/version/implementation.lua

TESTMODE=core

.PHONY: all clean release test github-release coverage install install-lua-luasodium $(INSTALL_LUAS) $(INSTALL_DLLS) $(INSTALL_LIBS) $(VERSION_FILES)
.SUFFIXES:

all: $(LUASODIUM_DLLS) $(LUASODIUM_LIBS) $(LUASODIUM_LUAS)

define VERSION_TEMPLATE
$(1):
	sed -e "s/@LUASODIUM_VERSION_MAJOR@/$(VERSION_MAJOR)/; s/@LUASODIUM_VERSION_MINOR@/$(VERSION_MINOR)/; s/@LUASODIUM_VERSION_PATCH@/$(VERSION_PATCH)/" < $(1).in > $(1)
endef

$(foreach f,$(VERSION_FILES),$(eval $(call VERSION_TEMPLATE,$(f))))

c/luasodium/luasodium.o: c/luasodium/luasodium.c
	$(CC) $(CFLAGS) -o $@ -c $<

%/core.o: %/core.c %/constants.h
	$(CC) $(CFLAGS) -o $@ -c $<

%/ffi.o: %/ffi.c %/constants.h
	$(CC) $(CFLAGS) -o $@ -c $<

c/luasodium$(DLL): $(LUASODIUM_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

c/luasodium$(LIB): $(LUASODIUM_OBJS)
	ar rcs $@ $^

test-%: $(LUASODIUM_DLLS) $(LUASODIUM_LIBS) $(LUASODIUM_LUAS)
	busted -c --lua=$(shell which $(LUA)) --lpath 'lua/?.lua' --cpath 'c/?.so' spec/$(@:test-%=%)_spec.lua

test: $(LUASODIUM_TESTS)

clean:
	rm -f $(LUASODIUM_DLLS)
	rm -f $(LUASODIUM_OBJS)
	rm -f $(LUASODIUM_LIBS)
	rm -f $(LUASODIUM_GCDA)
	rm -f $(LUASODIUM_GCNO)
	rm -f $(VERSION_FILES)

release: $(VERSION_FILES)
	rm -rf luasodium-$(VERSION_NUM) dist/luasodium-$(VERSION_NUM)
	rm -rf dist/luasodium-$(VERSION_NUM).tar.gz
	rm -rf dist/luasodium-$(VERSION_NUM).tar.xz
	rm -f $(LUASODIUM_OBJS) $(LUASODIUM_DLLS) $(LUASODIUM_LIBS)
	rm -f $(LUASODIUM_GCNO)
	rm -f $(LUASODIUM_GCDA)
	make -C tools clean
	mkdir -p dist
	mkdir -p luasodium-$(VERSION_NUM)/
	rsync -a --exclude '*.in' cmake luasodium-$(VERSION_NUM)/
	rsync -a --exclude '*.in' c luasodium-$(VERSION_NUM)/
	rsync -a --exclude '*.in' lua luasodium-$(VERSION_NUM)/
	rsync -a --exclude '*.in' spec luasodium-$(VERSION_NUM)/
	rsync -a --exclude '*.in' test luasodium-$(VERSION_NUM)/
	rsync -a --exclude '*.in' tools luasodium-$(VERSION_NUM)/
	rsync -a README.md luasodium-$(VERSION_NUM)/README.md
	rsync -a LICENSE luasodium-$(VERSION_NUM)/LICENSE
	rsync -a Makefile luasodium-$(VERSION_NUM)/Makefile
	rsync -a CMakeLists.txt luasodium-$(VERSION_NUM)/CMakeLists.txt
	rsync -a dist.ini luasodium-$(VERSION_NUM)/dist.ini
	sed 's/@VERSION@/$(VERSION_NUM)/g' < rockspecs/luasodium-release-template.rockspec > luasodium-$(VERSION_NUM)/luasodium-$(VERSION_NUM)-1.rockspec
	sed 's/@VERSION@/$(VERSION_NUM)/g' < dist.ini > luasodium-$(VERSION_NUM)/dist.ini
	tar cvf dist/luasodium-$(VERSION_NUM).tar luasodium-$(VERSION_NUM)
	gzip -k dist/luasodium-$(VERSION_NUM).tar
	xz dist/luasodium-$(VERSION_NUM).tar
	mv luasodium-$(VERSION_NUM) dist/luasodium-$(VERSION_NUM)

github-release:
	source $(HOME)/.github-token && github-release release \
	  --user jprjr \
	  --repo luasodium \
	  --tag v$(VERSION_NUM)
	source $(HOME)/.github-token && github-release upload \
	  --user jprjr \
	  --repo luasodium \
	  --tag v$(VERSION_NUM) \
	  --name luasodium-$(VERSION_NUM).tar.gz \
	  --file dist/luasodium-$(VERSION_NUM).tar.gz
	source $(HOME)/.github-token && github-release upload \
	  --user jprjr \
	  --repo luasodium \
	  --tag v$(VERSION_NUM) \
	  --name luasodium-$(VERSION_NUM).tar.xz \
	  --file dist/luasodium-$(VERSION_NUM).tar.xz

define LUA_INSTALL
install-lua-$(1):
	install -Dm0644 lua/luasodium/$(1).lua $(DESTDIR)$(INSTALL_LMOD)/luasodium/$(1).lua
endef

install-dll-luasodium: c/luasodium$(DLL)
	install -Dm0755 c/luasodium$(DLL) $(DESTDIR)$(INSTALL_CMOD)/luasodium$(DLL)

install-lib-luasodium: c/luasodium$(LIB)
	install -Dm0644 c/luasodium$(LIB) $(DESTDIR)$(INSTALL_CMOD)/luasodium$(LIB)

install-lua-luasodium:
	install -Dm0644 lua/luasodium.lua $(DESTDIR)$(INSTALL_LMOD)/luasodium.lua

$(foreach mod,$(LUASODIUM_MODS),$(eval $(call LUA_INSTALL,$(mod))))
$(foreach mod,$(LUASODIUM_MODS),$(eval $(call DLL_INSTALL,$(mod))))
$(foreach mod,$(LUASODIUM_MODS),$(eval $(call LIB_INSTALL,$(mod))))

install-luas: $(INSTALL_LUAS)

install: install-luas install-dll-luasodium install-lib-luasodium

coverage-collect-c:
	gcovr -r . --json -o $(TESTMODE)-c-coverage.json

coverage-collect-lua:
	luacov -r gcovr
	mv luacov.report.out $(TESTMODE)-lua-coverage.json

coverage-run:
	busted -c --lua="$(shell which $(LUA))" --lpath 'lua/?.lua' --cpath 'c/?.so' --verbose

# wrapper job for running each coverage job
coverage:
	rm -rf coverage
	rm -f *.json
	rm -f luacov.stats.out luacov.report.out
	mkdir -p coverage
	$(MAKE) -f Makefile clean
	$(MAKE) -f Makefile LDFLAGS="--coverage $(shell $(PKGCONFIG) --libs libsodium)" CFLAGS="-fPIC -Wall -Wextra -g -O0 -fprofile-arcs -ftest-coverage --coverage $(shell $(PKGCONFIG) --cflags $(LUA)) $(shell $(PKGCONFIG) --cflags libsodium)" LUA=$(LUA)
	$(MAKE) -f Makefile LUA=$(LUA) TESTMODE=core coverage-run
	$(MAKE) -f Makefile LUA=$(LUA) TESTMODE=core coverage-collect-c
	$(MAKE) -f Makefile LUA=$(LUA) TESTMODE=core coverage-collect-lua
	$(MAKE) -f Makefile LUA=$(LUA) TESTMODE=ffi coverage-run
	$(MAKE) -f Makefile LUA=$(LUA) TESTMODE=ffi coverage-collect-c
	$(MAKE) -f Makefile LUA=$(LUA) TESTMODE=ffi coverage-collect-lua
	$(MAKE) -f Makefile LUA=$(LUA) TESTMODE=pureffi coverage-run
	$(MAKE) -f Makefile LUA=$(LUA) TESTMODE=pureffi coverage-collect-lua
	gcovr --html-details coverage/index.html $(addprefix --add-tracefile ,$(foreach cmode,core ffi,$(cmode)-c-coverage.json) $(foreach lmode,core ffi pureffi,$(lmode)-lua-coverage.json))
	gcovr --xml coverage/index.xml $(addprefix --add-tracefile ,$(foreach cmode,core ffi,$(cmode)-c-coverage.json) $(foreach lmode,core ffi pureffi,$(lmode)-lua-coverage.json))

echo:
	echo $(VERSION)
	echo $(VERSION_MAJOR)
	echo $(VERSION_MINOR)
	echo $(VERSION_PATCH)
