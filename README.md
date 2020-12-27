# luasodium

Bindings to [Libsodium](https://libsodium.gitbook.io/doc/), with support
for the Lua C API as well as LuaJIT's FFI API.

This is meant to follow the Libsodium API closely, with a few Lua idioms.
I will document all functions and highlight variations from the Libsodium
C API.

Luasodium is broken into sub-modules, based on function prefixes in
the Libsodium API. For example, all the `randombytes_` function are
in a `luasodium.randombytes` module.

So far this covers:

* Helper and Padding Functions
  * [`sodium_init`](https://libsodium.gitbook.io/doc/usage)
  * [Helpers](https://libsodium.gitbook.io/doc/helpers)
  * [Padding](https://libsodium.gitbook.io/doc/padding)
* [Generating Random Data](https://libsodium.gitbook.io/doc/generating_random_data)

## Module Documentation

### `luasodium`

#### Synopsis:

```lua
local luasodium = require'luasodium'
luasodium.init()
```

#### Functions:

* `luasodium.init()`

* Initializes the library, must be called before any other function.
* Returns `true` on success, `false` otherwise.

* `luasodium.memcmp(b1,b2,size)`

* Compares two 
