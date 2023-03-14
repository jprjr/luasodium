# luasodium

[![codecov](https://codecov.io/gh/jprjr/luasodium/branch/main/graph/badge.svg?token=5vQm3fchNl)](https://codecov.io/gh/jprjr/luasodium)

Bindings to [Libsodium](https://libsodium.gitbook.io/doc/), with support
for the Lua C API as well as LuaJIT's FFI API.

There's basically three methods for loading the API, they're tried in
this order:

1. FFI API from a C module, with function pointers.
2. Traditional C API
3. FFI API, using `ffi.load` to load `libsodium` at runtime.

If you'd like to load a specific version, you can append:

* `.ffi` (to use FFI via pointers in a C module)
* `.core` (to use the traditional C API).
* `.pureffi` (to use FFI and find/load `libsodium` at runtime).

The `.core` and `.ffi` variants don't exist in the OpenResty
Package Manager version, since OPM doesn't support C
modules.

Example:

```lua
local luasodium         = require'luasodium'          -- tries to load FFI, fallback to C API
local luasodium_ffi     = require'luasodium.ffi'      -- uses the FFI API (in a C module)
local luasodium_c       = require'luasodium.core'     -- uses the C API
local luasodium_pureffi = require'luasodium.pureffi'  -- uses the FFI API (without any C modules)
```

## Status

### Version 1.0

As of version `1.0.0`, this module covers:

* All original, high-level functions from [NaCl](http://nacl.cr.yp.to/index.html)
(crypto\_box, crypto\_secretbox, and so on).
* All of libsodium's additions to NaCl's high-level functions (crypto\_box\_easy,
crypto\_secretbox\_easy).
* All of libsodium's utility functions and random data generating functions.

It does not yet cover the entire libsodium API.

Details on what functions were implemented can be found under the
[Version 1.0.0 Milestone](https://github.com/jprjr/luasodium/milestone/1).

### Version 1.1

* All original lower-level functions from NaCl (crypto\_box\_curve25519xsalsa20poly1305,
crypto\_secretbox\_xsalsa20poly1305). This means version 1.1 has 100% NaCl coverage.

### Version 1.2

* The libsodium `crypto_generichash` API.
* The libsodium `crypto_secretstream` API.

Details on what functions were implemented can be found under the
[Version 1.2.0 Milestone](https://github.com/jprjr/luasodium/milestone/3).

### Version 1.3

* The libsodium `crypto_shorthash` API.
* The libsodium `crypto_pwhash` API.

Details on what functions were implemented can be found under the
[Version 1.3.0 Milestone](https://github.com/jprjr/luasodium/milestone/5).

### Version 2.0

No functional changes, but an API change. `libsodium` errors no
longer throw errors, they return `nil` and an error message.

### Version 2.1

* The libsodium `crypto_aead` API.

Details on what functions were implemented can be found under the
[Version 2.1.0 Milestone](https://github.com/jprjr/luasodium/milestone/6).

### Version 2.2

This version no longer uses `malloc`/`free` and instead uses `sodium_malloc`
and `sodium_free`, for data allocations that require alignment. This
simplifies the FFI version somewhat - it no longer needs to load
the C library's `malloc`/`free`, and no longer needs wrappers to call
`sodium_memzero` when structures are garbage collected, since
`sodium_free` will take care of that.

This version also adds the scrypt pwhash functions.

### Version 2.3

This version removes the use of `sodium_malloc` and `sodium_free`
introduced in version 2.2. Per the libsodium docs:

> These are not general-purpose allocation functions. In particular, they are slower than malloc() and friends and require 3 or 4 extra pages of virtual memory.

I experienced segfaults, etc from running out of memory.

Rather than revert to the FFI version requiring `malloc` and `free`,
it instead uses LuaJIT's own memory management, with wrappers
to call `sodium_memzero` when garbage-collected.

This version also adds the `crypto_kx` functions.

## Caveats

`libsodium` includes functions for secure programming, like allocating
memory that avoids swapping, securely zeroing out memory, clearing
the stack, and so on.

I'm not sure how possible it is to implement these kinds of functions
in Lua. In Lua, I allocate memory using `lua_newuserdata` or LuaJIT's
`ffi.new()`, so that Lua can keep track of it and garbage collect it.
Before releasing temporary memory back to the garbage collector, I do
call `sodium_memzero` to wipe it - but this only applies to scratch
memory.

If you're concerned with making absolutely sure memory is cleared
out, you should likely code your secure portions in C and use
`libsodium`'s secure memory functions, or forego the standard
Lua interpreter and write something with a custom allocator
that uses `sodium_malloc` and `sodium_free`.

## Installation

### luarocks

Available on [luarocks](https://luarocks.org/modules/jprjr/luasodium):

```bash
luarocks install luasodium
```

### OPM

An FFI-only version is available on [OPM](https://opm.openresty.org/package/jprjr/luasodium/)

```bash
opm install jprjr/luasodium
```

### Arch Linux

Available on the AUR: [lua-luasodium](https://aur.archlinux.org/packages/lua-luasodium/).

Builds packages for lua, lua-5.1, lua-5.2, and lua-5.3.

### Source

Currently migrating to a CMake build system. Building and installing
the library with cmake works, I have not yet moved running tests, generating
release tarballs, etc into cmake.

If you'd like to build from source, grab
one of the release tarballs, and then build with cmake:

```bash
wget https://github.com/jprjr/luasodium/releases/download/v1.3.0/luasodium-1.3.0.tar.gz
tar xf luasodium-1.3.0.tar.gz
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr ../luasodium-1.3.0
make
make install
```

CMake should find libsodium and Lua automatically. Or you can specify some flags:

* `-DLUA_VERSION=5.1` (or whichever version of Lua you want to build against.
* `-DLIBSODIUM_INCLUDEDIR=/path/to/includedir -DLIBSODIUM_LIBRARIES=/path/to/libsodium.so`
* `-DLUA_INCLUDEDIR=/path/to/includedir`

If you set LUA_INCLUDEDIR, you'll need to also set LUA_VERSION. If you're building with
any version of LuaJIT, set it to `5.1`.


## Licensing

MIT License (see file `LICENSE`).

## Idioms

This is meant to follow the Libsodium API closely, with a few idioms.

### Idiom: Use original symbol names.

All functions and constants use their original, full name from `libsodium`.

### Idiom: Throw errors on programming errors

If a function is missing a parameter or has a wrong parameter type,
a Lua error is thrown.

If a call into libsodium returns an error value (example, a message
fails to decrypt), then `nil` is returned.

### Idiom: Auto-allocate strings/buffers.

If a `libsodium` function writes data into a buffer,
this library will automatically allocate and return
a string.

### Idiom: Handle zero-padding

The [original NaCl library](https://nacl.cr.yp.to/) requires the
user to have padding before messages and ciphertexts.

If a `libsodium` function requires padding, this library
will take care of it for you, you'll never need to add padding.


### Idiom: strings are immutable.

If a `libsodium` function changes a buffer, this
library will instead make a copy, make changes
in that, and return the copy.

### Idiom: Use input string length.

If a `libsodium` function accepts a buffer and a buffer
length, the Lua version will just accept a Lua string, you
can use `string.sub` if you need to call a function with
a substring.


### Idiom examples:

In `libsodium`, converting a string to hex is:

```c
sodium_bin2hex(char * const hex, const size_t hex_maxlen,
               const unsgined char *const bin, const size_t bin_len);
```

Since this library will automatically allocate `hex`, and
uses your string's length, the Lua version is simply:

```lua
local string = luasodium.sodium_bin2hex(some_other_string)
```

In `libsodium`, you can perform addition, subtraction, etc
on large integers, these operations are performed on the
buffer directly, such as:

```c
char buf[4] = { 0, 0, 0, 0};
sodium_increment(buf,4);
/* buf is now { 1, 0 , 0, 0 } */
```

In Lua, we instead create a new buffer, copy it, increment,
and return that.

```lua
local buf = string.rep('\0',4)

local incremented = luasodium.sodium_increment(buf)
-- buf is still '\0\0\0\0', incremented is '\1\0\0\0'
```

## Modules

Luasodium is broken into submodules, though these are mostly used
for testing and verification - the recommended approach is to
just require `luasodium`. This will return a module with
all functions and constants from the submodules in a single
table.

Documentation on modules is available in [the wiki](https://github.com/jprjr/luasodium/wiki/Modules).

