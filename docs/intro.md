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

