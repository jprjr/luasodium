# luasodium

Bindings to [Libsodium](https://libsodium.gitbook.io/doc/), with support
for the Lua C API as well as LuaJIT's FFI API.

The FFI API is loaded from within the C module via function pointers,
this allows the FFI API to work in static binaries, and remove the need
to search for a library with `ffi.load` (since the C module will already
be linked to `libsodium` and have references to the needed functions).

## Idioms

This is meant to follow the Libsodium API closely, with a few Lua idioms.

### Throw errors

If a function is missing a parameter, has a wrong parameter type,
or a call into `libsodium` returns an error value, a Lua error
is thrown.

### Auto-allocate strings/buffers, strings are immutable.

If a `libsodium` function writes data into a buffer,
this library will automatically allocate and return
a string.

If a `libsodium` function changes a buffer, this
library will instead make a copy, make changes
in that, and return the copy.

### Use input string length

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
local string = luasodium.bin2hex(some_other_string)
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

local incremented = luasodium.increment(buf)
-- buf is still '\0\0\0\0', incremented is '\1\0\0\0'
```

## Modules

Luasodium is broken into sub-modules, based on function prefixes in
the Libsodium API. For example, all the `randombytes_` function are
in a `luasodium.randombytes` module.

So far there's two modules:

* `luasodium`
* `luasodium.randombytes`

So far this covers:

* Helper and Padding Functions
  * [`sodium_init`](https://libsodium.gitbook.io/doc/usage)
  * [Helpers](https://libsodium.gitbook.io/doc/helpers)
  * [Padding](https://libsodium.gitbook.io/doc/padding)
* [Generating Random Data](https://libsodium.gitbook.io/doc/generating_random_data)

## Module Documentation

### `luasodium`

#### Synopsis:

The base `luasodium` module provides an `init` function, and helper
functions for padding strings, encoding/decoding base64, handling
large integers, etc.

```lua
local luasodium = require'luasodium'
luasodium.init()
```

#### Functions:

##### `bool = luasodium.init()`

* Initializes the library, must be called before any other function.
* Returns `true` on success, `false` otherwise.

##### `bool = luasodium.memcmp(b1,b2,size)`

* Compares two lua strings (`b1`, `b2`) up to (`size`) bytes.
* Returns `true` if strings are equal.

##### `string = luasodium.bin2hex(bin)`

* Converts a lua string (`bin`) into a hex string.
* Returns the hex string.

##### `string, string = luasodium.hex2bin(hex [,ignore])`

* Converts a lua string (`hex`) up to (`hex_len`) bytes into a binary string.
* Accepts an optional parameter (`ignore`) with characters to ignore during conversions.
* Returns the binary string, and the remainder of the hex input, if any.

##### `string = luasodium.bin2base64(bin,variant)`

* Converts a lua string (`bin`) into a base64 string.
* Second parameter (`variant`) is the base64 variant to use, available
values:
    * `luasodium.base64_VARIANT_ORIGINAL`
    * `luasodium.base64_VARIANT_ORIGINAL_NO_PADDING`
    * `luasodium.base64_VARIANT_URLSAFE`
    * `luasodium.base64_VARIANT_URLSAFE_NO_PADDING`

##### `string, string = luasodium.base642bin(base64, variant [,ignore])`

* Converts a lua string (`base64`) into a binary string.
* Second parameter (`variant`) is the base64 variant to use, see above for available values.
* Third optional parameter is a string of characters to ignore.
* Returns the binary string, and the remainder of the base64 input, if any.

##### `string = luasodium.increment(string)`

* Increments an arbitrary string.
* String is assumed to be unsigned, little-endian encoded, example:
    * `'\1\0\0\0'` = `1`
    * `'\0\0\0\1'` = `65536`
* Returns the incremented value as a new string.

##### `string = luasodium.add(string,string)`

* Adds two strings.
* Like `luasodium.increment`, string is unsigned, little-endian.
* Both strings need to be the same length.
* Returns the sum as a new string.

##### `string = luasodium.sub(string,string)`

* Substracts string 2 from string 1.
* Like `luasodium.increment`, string is unsigned, little-endian.
* Both strings need to be the same length.
* Returns the difference as a new string.

##### `integer = luasodium.compare(string,string)`

* Compares strings
* Like `luasodium.increment`, string is unsigned, little-endian.
* Both strings need to be the same length.
* Returns:
    * `-1` if string1 < string 2
    * `0` if string 1 == string 2
    * `1` if string 1 > string 2

##### `bool = luasodium.is_zero(string)`

* Tests if all bytes in a string is zero.
* Returns `true` if all bytes are zero.

##### `string = luasodium.pad(string,blocksize)`

* Pads a `string` to be a multiple of `blocksize`
* Returns the new, padded string.

##### `string = luasodium.unpad(string,blocksize)`

* Removes padding from `string`.
* Returns a new, unpadded string.
