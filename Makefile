.PHONY: all clean

HOST_CC = cc
PKGCONFIG = pkg-config
LUA = lua5.1

LUASODIUM_OBJS = \
  luasodium.o \
  luasodium/randombytes.o

LUASODIUM_DLLS = \
  luasodium.so \
  luasodium/randombytes.so

LUASODIUM_FFIS = \
  luasodium.luah \
  luasodium/randombytes.luah

CFLAGS=$(shell $(PKGCONFIG) --cflags libsodium)
LDFLAGS=$(shell $(PKGCONFIG) --libs libsodium)

CFLAGS += -fPIC -Wall -Wextra -g -O0 -DDEBUG=1
CFLAGS += $(shell $(PKGCONFIG) --cflags $(LUA))

all: $(LUASODIUM_DLLS)

%.so: %.o
	$(CC) -shared -o $@ $^ $(LDFLAGS)

luasodium.o: luasodium.c luasodium.luah
	$(CC) $(CFLAGS) -o $@ -c $<

luasodium/randombytes.o: luasodium/randombytes.c luasodium/randombytes.luah
	$(CC) $(CFLAGS) -o $@ -c $<

%.luah: %-ffi.lua aux/bin2c
	./aux/bin2c $< $@ $(patsubst %.luah,%_ffi,$(notdir $@))

aux/bin2c: aux/bin2c.c
	$(HOST_CC) -o $@ $^

clean:
	rm -f aux/bin2c $(LUASODIUM_DLLS) $(LUASODIUM_OBJS) $(LUASODIUM_FFIS)
