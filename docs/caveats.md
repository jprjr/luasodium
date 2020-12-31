## Caveats

`libsodium` includes functions for secure programming, like allocating
memory that avoids swapping, securely zeroing out memory, clearing
the stack, and so on.

I'm not sure how possible it is to implement these kinds of functions
in Lua. In Lua, I allocate memory using `lua_newuserdata` or LuaJIT's
`ffi.new()`, so that Lua can keep track of it and garbage collect it.

I could write wrappers around these methods that use metatables to
free memory, but then you get into how to access/use the memory -
should it be like an array, and you get/set single bytes?

If you're concerned with making absolutely sure memory is cleared
out, you should likely code your secure portions in C and use
`libsodium`'s secure memory functions.

