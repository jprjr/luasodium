## Installation

Available on [luarocks](https://luarocks.org/modules/jprjr/luasodium):

```bash
luarocks install luasodium
```

An FFI-only version is available on [OPM](https://opm.openresty.org/package/jprjr/luasodium/)

```bash
opm install jprjr/luasodium
```

Alternatively, if you'd like to build from source, grab
one of the release tarballs (not the automatically-generated .tar.gz files).
This will have pre-compiled Lua includes for the FFI portion of the library.

```bash
wget https://github.com/jprjr/luasodium/releases/download/v0.0.5/luasodium-0.0.5.tar.gz
tar xf luasodium-0.0.5.tar.gz
cd luasodium-0.0.5
make
```

I still need to write a `make install` target, and
update the Makefile for supporting Windows.

