.PHONY: all clean

PKGCONFIG = pkg-config
LUA = lua5.1

CORE_OBJS = \
  luasodium/core.o

CFLAGS=$(shell $(PKGCONFIG) --cflags libsodium)
LDFLAGS=$(shell $(PKGCONFIG) --libs libsodium)

CFLAGS += -Wall -Wextra -g -O0
CFLAGS += $(shell $(PKGCONFIG) --cflags $(LUA))

all: luasodium/core.so

luasodium/core.so: $(CORE_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(CORE_OBJS) core.so
