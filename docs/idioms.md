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

### Idiom: `easy`-like wrappers.

The [original NaCl library](https://nacl.cr.yp.to/) requires the
user to have padding before messages and ciphertexts. `libsodium` has
*some* versions of functions that handle padding, but not
everywhere. Example, there's a `crypto_secretbox_xsalsapoly1305`
function, but no `crypto_secretbox_xsalsapoly1305_easy` function.

This library will take care of adding padding, you do **not**
need to prefix your messages and ciphertexts with padding
bytes. You can call `crypto_secretbox` and
`crypto_secretbox_easy` with the same parameters and get
the same result.

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

