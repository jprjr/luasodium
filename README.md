# luasodium

Bindings to [Libsodium](https://libsodium.gitbook.io/doc/), with support
for the Lua C API as well as LuaJIT's FFI API.

The FFI API is loaded from within the C module via function pointers,
this allows the FFI API to work in static binaries, and remove the need
to search for a library with `ffi.load` (since the C module will already
be linked to `libsodium` and have references to the needed functions).

## Caveats

`libsodium` includes function for secure programming, like allocating
memory that avoids swapping, securely zeroing out memory, clearing
the stack, and so on.

I'm not sure how possible it is to implement these kinds of functions
in Lua. In Lua, I allocate memory using `lua_newuserdata` or LuaJIT's
`ffi.new()`, so that Lua can keep track of it and garbage collect it.

If you're concerned with making absolutely sure memory is cleared
out, you should likely code your secure portions in C and use the
`libsodium`'s secure memory functions.

## Licensing

MIT License (see file `LICENSE`).

## Idioms

This is meant to follow the Libsodium API closely, with a few Lua idioms.

### Idiom: Throw errors

If a function is missing a parameter, has a wrong parameter type,
or a call into `libsodium` returns an error value, a Lua error
is thrown.

### Idiom: Auto-allocate strings/buffers, strings are immutable.

If a `libsodium` function writes data into a buffer,
this library will automatically allocate and return
a string.

If a `libsodium` function changes a buffer, this
library will instead make a copy, make changes
in that, and return the copy.

### Idiom: Use input string length

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
in a `luasodium.randombytes` module. I've tried to organize them
based on where/when they appear in the `libsodium` documentation.

Here's the completed modules:

* `luasodium`: covers
    * ["Usage"](https://libsodium.gitbook.io/doc/usage)
    * ["Helpers"](https://libsodium.gitbook.io/doc/helpers)
    * ["Padding"](https://libsodium.gitbook.io/doc/padding)
* `luasodium.randombytes`: covers
    * ["Generating Random Data"](https://libsodium.gitbook.io/doc/generating_random_data)
* `luasodium.crypto_secretbox`: covers
    * ["Secret-key cryptography: Authenticated encryption"](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox)

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

#### Constants

* `luasodium.base64_VARIANT_ORIGINAL`
* `luasodium.base64_VARIANT_ORIGINAL_NO_PADDING`
* `luasodium.base64_VARIANT_URLSAFE`
* `luasodium.base64_VARIANT_URLSAFE_NO_PADDING`

#### Functions:

##### `bool success = luasodium.init()`

* Initializes the library, must be called before any other function.
* Returns `true` on success, throws an error otherwise.

##### `bool equal = luasodium.memcmp(string b1,string b2,number size)`

* Compares two lua strings (`b1`, `b2`) up to (`size`) bytes.
* Returns `true` if strings are equal.

##### `string hex = luasodium.bin2hex(string bin)`

* Converts a lua string (`bin`) into a hex string.
* Returns the hex string.

##### `string bin, string remain = luasodium.hex2bin(string hex [,string ignore])`

* Converts a lua string (`hex`) up to (`hex_len`) bytes into a binary string.
* Accepts an optional parameter (`ignore`) with characters to ignore during conversions.
* Returns the binary string, and the remainder of the hex input, if any.

##### `string base64 = luasodium.bin2base64(string bin,number variant)`

* Converts a lua string (`bin`) into a base64 string.
* Second parameter (`variant`) is the base64 variant to use, available
values:
    * `luasodium.base64_VARIANT_ORIGINAL`
    * `luasodium.base64_VARIANT_ORIGINAL_NO_PADDING`
    * `luasodium.base64_VARIANT_URLSAFE`
    * `luasodium.base64_VARIANT_URLSAFE_NO_PADDING`

##### `string bin, string remain = luasodium.base642bin(string base64, number variant [,string ignore])`

* Converts a lua string (`base64`) into a binary string.
* Second parameter (`variant`) is the base64 variant to use, see above for available values.
* Third optional parameter is a string of characters to ignore.
* Returns the binary string, and the remainder of the base64 input, if any.

##### `string incremented = luasodium.increment(string value)`

* Increments an arbitrary string.
* String is assumed to be unsigned, little-endian encoded, example:
    * `'\1\0\0\0'` = `1`
    * `'\0\0\0\1'` = `65536`
* Returns the incremented value as a new string.

##### `string sum = luasodium.add(string value1, string value2)`

* Adds two values.
* Like `luasodium.increment`, string is unsigned, little-endian.
* Both strings need to be the same length.
* Returns the sum as a new string.

##### `string diff = luasodium.sub(string value1, string value2)`

* Subtracts value2 from value1.
* Like `luasodium.increment`, string is unsigned, little-endian.
* Both strings need to be the same length.
* Returns the difference as a new string.

##### `integer result = luasodium.compare(string value1, string value2)`

* Compares strings
* Like `luasodium.increment`, string is unsigned, little-endian.
* Both strings need to be the same length.
* Returns:
    * `-1` if `value1` < `value2`
    * `0` if `value1` == `value2`
    * `1` if `value1` > `value2`

##### `bool zero = luasodium.is_zero(string value)`

* Tests if all bytes in a string is zero.
* Returns `true` if all bytes are zero, `false` otherwise.

##### `string padded = luasodium.pad(string original, number blocksize)`

* Pads a `string` to be a multiple of `blocksize`
* Returns the new, padded string.

##### `string original = luasodium.unpad(string padded, number blocksize)`

* Removes padding from `string`.
* Returns a new, unpadded string.

### `luasodium.randombytes`

#### Synopsis

The `randombytes` module provides functions for getting random data.

```lua
require('luasodium').init()
local randombytes = require'luasodium.randombytes'

print(randombytes.random()) -- prints a random number
```

#### Constants

* `randombytes.SEEDBYTES` - required length of a seed string (32 bytes).

#### Functions

##### `number rand = randombytes.random()`

Returns a random, unsigned 32-bit integer.

##### `number rand = randombytes.uniform(number upper_bound)`

Returns a random, unsigned integer between 0 and the provided number (exclusive).

##### `string rand = randombytes.buf(number length)`

Returns a string of random bytes - `length` is the length of the string to generate.

##### `string rand = randombytes.buf_deterministic(number length, string seed)`

Returns a string of random bytes.

* `length` is the length of the string to generate.
* `seed` is a Lua string to use as a seed, must be 32 bytes long.

##### `boolean success = randombytes.close()`

Deallocates global resources used by the pseudo-random number generator.

##### `randombytes.stir()`

Reseeds the pseudo-random number generator.

### `luasodium.crypto_secretbox`

Wrapper for the `crypto_secretbox_` functions.

#### Synopsis

```lua
require('luasodium').init()
local crypto_secretbox = require'luasodium.crypto_secretbox'

local message = 'my message to encrypto'
local nonce = string.rep('\0', crypto_secretbox.NONCEBYTES)
local key = string.rep('\0', crypto_secretbox.KEYBYTES)

assert(
  crypto_secretbox.open_easy(
    crypto_secretbox.easy(message,nonce,key),
    nonce,
    key
  ) == message
)
```

#### Constants

* `crypto_secretbox.KEYBYTES` - valid key length
* `crypto_secretbox.NONCEBYTES` - valid nonce length
* `crypto_secretbox.MACBYTES` - valid MAC length

#### Functions

##### `string cipher = crypto_secretbox.easy(string message, string nonce, string key)`

* Encrypts `message` using `nonce` and `key`.
* Returns the encrypted message.

##### `string message = crypto_secretbox.open_easy(string cipher, string nonce, string key)`

* Decrypts `cipher` using `nonce` and `key`.
* Returns the plain-text message.

##### `string cipher, string mac = crypto_secretbox.detached(string message, string nonce, string key)`

* Encrypts `message` using `nonce` and `key`.
* Returns the encrypted message and the MAC as separate strings.

##### `string message = crypto_secretbox.open_detached(string cipher, string mac, string nonce, string key)`

* Decrypts `cipher` with `mac`, `nonce`, and `key`.
* Returns the plain-text message.
