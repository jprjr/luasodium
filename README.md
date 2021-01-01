# luasodium

Bindings to [Libsodium](https://libsodium.gitbook.io/doc/), with support
for the Lua C API as well as LuaJIT's FFI API.

By default, all modules attempt to load the FFI API, then fallback
to the C API. If you want more control over which version you're using,
you can append `.core` to a module to load the C API, or `.ffi` to
load the FFI API.

The `.core` and `.ffi` variants don't exist in the OpenResty
Package Manager version, since its FFI only. You just use
regular module names in that case.

Example:

```lua
local luasodium     = require'luasodium'      -- tries to load FFI, fallback to C API
local luasodium_c   = require'luasodium.core' -- uses the C API only
local luasodium_ffi = require'luasodium.ffi'  -- uses the FFI API only
```

The FFI API is loaded inside a C module via function pointers,
this allows the FFI API to work in static binaries, and remove the need
to search for a library with `ffi.load` (since the C module will already
be linked to `libsodium` and have references to the needed functions).

If you're in an environment where building a C module is difficult,
but using the FFI API is fine, you can also just use the modules under
the `ffi/` folder directly. They detect if they're being loaded
from the C module, or if they're being loaded as regular modules.
This is how the version on [OPM](https://opm.openresty.org/package/jprjr/luasodium/)
is published, since OPM doesn't allow C modules. In this case,
it will use `ffi.load` to locate the `sodium` library.

## Status and roadmap

I noticed that a lot of `libsodium` functions are pretty similar, so
I initially tried using closures to encapsulate functions. This wound
up creating a lot of overhead on my part - I created structures
to track everything, and had closures referencing those structures.

Now I just have a 1-to-1 mapping of a `libsodium` function
to a Lua wrapper. I may revisit this and go with a simpler
closure implementation in the future.

I don't plan to cover *all* the libsodium API, at least not for
version `1.0.0`. There's a lot of low-level functions that
libsodium [is planning to remove](https://github.com/jedisct1/libsodium/issues/1017),
so I'm going to prioritize covering the high-level functions.

I'll mark this as version `1.0.0` when I've covered all the original,
high-level [NaCl](https://nacl.cr.yp.to/index.html) functions, and
any equivalent "easy"/"detached" variants that `libsodium` has added.
I think at that point, this library should be pretty usable.

The issues under the [Version 1.0.0 Milestone](https://github.com/jprjr/luasodium/milestone/1)
list out all the functions that will be covered in a 1.0.0 release.

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

## Licensing

MIT License (see file `LICENSE`).

## Idioms

This is meant to follow the Libsodium API closely, with a few idioms.

### Idiom: Use original symbol names.

All functions and constants use their original, full name from `libsodium`.

### Idiom: Throw errors.

If a function is missing a parameter, has a wrong parameter type,
or a call into `libsodium` returns an error value, a Lua error
is thrown.

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

Luasodium is broken into sub-modules, based on function prefixes in
the Libsodium API. For example, all the `randombytes` function are
in a `luasodium.randombytes` module.

There's a global `luasodium` module that includes all submodules,
you don't have to include each and every module.

Documentation on modules is available in [the wiki](https://github.com/jprjr/luasodium/wiki/Modules).
