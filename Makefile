.PHONY: all clean

PKGCONFIG = pkg-config
LUA = lua5.1

LUASODIUM_OBJS = \
  luasodium/core.o \
  luasodium/randombytes/core.o

LUASODIUM_DLLS = \
  luasodium/core.so \
  luasodium/randombytes/core.so

CFLAGS=$(shell $(PKGCONFIG) --cflags libsodium)
LDFLAGS=$(shell $(PKGCONFIG) --libs libsodium)

CFLAGS += -Wall -Wextra -g -O0
CFLAGS += $(shell $(PKGCONFIG) --cflags $(LUA))

all: $(LUASODIUM_DLLS)

%.so: %.o
	$(CC) -shared -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(LUASODIUM_DLLS) $(LUASODIUM_OBJS)
