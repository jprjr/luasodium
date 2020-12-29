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

## Modules

Luasodium is broken into sub-modules, based on function prefixes in
the Libsodium API. For example, all the `randombytes_` function are
in a `luasodium.randombytes` module. I've tried to organize them
based on where/when they appear in the `libsodium` documentation.

There's a global `luasodium` module that includes all submodules,
you don't have to include each and every module.

Here's the completed modules:

* [`luasodium.utils`](#luasodium-1): covers
    * ["Usage"](https://libsodium.gitbook.io/doc/usage)
    * ["Helpers"](https://libsodium.gitbook.io/doc/helpers)
    * ["Padding"](https://libsodium.gitbook.io/doc/padding)
* [`luasodium.randombytes`](#luasodiumrandombytes): covers
    * ["Generating Random Data"](https://libsodium.gitbook.io/doc/generating_random_data)
* [`luasodium.crypto_secretbox`](#luasodiumcrypto_secretbox): covers
    * ["Secret-key cryptography: Authenticated encryption"](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox)
* [`luasodium.crypto_box`](#luasodiumcrypto_box): covers
    * ["Public-key cryptography: Authenticated encryption"](https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption)
* [`luasodium.crypto_scalarmult`](#luasodiumcrypto_scalarmult): covers
    * ["Advanced: Point*scalar multiplication"](https://libsodium.gitbook.io/doc/advanced/scalar_multiplication)


## Module Documentation

### `luasodium.utils`

#### Synopsis:

The base `luasodium.utils` module provides helper
functions for padding strings, encoding/decoding base64, handling
large integers, etc.

```lua
local utils = require'luasodium.utils'
utils.sodium_bin2base64('some data',utils.sodium_base64_VARIANT_ORIGINAL)
```

#### Constants

* `utils.sodium_base64_VARIANT_ORIGINAL`
* `utils.sodium_base64_VARIANT_ORIGINAL_NO_PADDING`
* `utils.sodium_base64_VARIANT_URLSAFE`
* `utils.sodium_base64_VARIANT_URLSAFE_NO_PADDING`

#### Functions:

##### `bool success = utils.sodium_init()`

* Initializes the library.
* Returns `true` on success, throws an error otherwise.
* This is automatically called when the module is loaded,
and included just for completeness.

##### `bool equal = utils.sodium_memcmp(string b1,string b2,number size)`

* Compares two lua strings (`b1`, `b2`) up to (`size`) bytes.
* Returns `true` if strings are equal.

##### `string hex = utils.sodium_bin2hex(string bin)`

* Converts a lua string (`bin`) into a hex string.
* Returns the hex string.

##### `string bin, string remain = utils.sodium_hex2bin(string hex [,string ignore])`

* Converts a lua string (`hex`) into a binary string.
* Accepts an optional parameter (`ignore`) with characters to ignore during conversions.
* Returns the binary string, and the remainder of the hex input, if any.

##### `string base64 = utils.sodium_bin2base64(string bin,number variant)`

* Converts a lua string (`bin`) into a base64 string.
* Second parameter (`variant`) is the base64 variant to use, available
values:
    * `utils.sodium_base64_VARIANT_ORIGINAL`
    * `utils.sodium_base64_VARIANT_ORIGINAL_NO_PADDING`
    * `utils.sodium_base64_VARIANT_URLSAFE`
    * `utils.sodium_base64_VARIANT_URLSAFE_NO_PADDING`

##### `string bin, string remain = utils.sodium_base642bin(string base64, number variant [,string ignore])`

* Converts a lua string (`base64`) into a binary string.
* Second parameter (`variant`) is the base64 variant to use, see above for available values.
* Third optional parameter is a string of characters to ignore.
* Returns the binary string, and the remainder of the base64 input, if any.

##### `string incremented = utils.sodium_increment(string value)`

* Increments an arbitrary string.
* String is assumed to be unsigned, little-endian encoded, example:
    * `'\1\0\0\0'` = `1`
    * `'\0\0\0\1'` = `65536`
* Returns the incremented value as a new string.

##### `string sum = utils.sodium_add(string value1, string value2)`

* Adds two values.
* Like `utils.sodium_increment`, string is unsigned, little-endian.
* Both strings need to be the same length.
* Returns the sum as a new string.

##### `string diff = utils.sodium_sub(string value1, string value2)`

* Subtracts value2 from value1.
* Like `utils.sodium_increment`, string is unsigned, little-endian.
* Both strings need to be the same length.
* Returns the difference as a new string.

##### `integer result = utils.sodium_compare(string value1, string value2)`

* Compares strings
* Like `utils.sodium_increment`, string is unsigned, little-endian.
* Both strings need to be the same length.
* Returns:
    * `-1` if `value1` < `value2`
    * `0` if `value1` == `value2`
    * `1` if `value1` > `value2`

##### `bool zero = utils.sodium_is_zero(string value)`

* Tests if all bytes in a string is zero.
* Returns `true` if all bytes are zero, `false` otherwise.

##### `string padded = utils.sodium_pad(string original, number blocksize)`

* Pads a `string` to be a multiple of `blocksize`
* Returns the new, padded string.

##### `string original = utils.sodium_unpad(string padded, number blocksize)`

* Removes padding from `string`.
* Returns a new, unpadded string.

### `luasodium.randombytes`

#### Synopsis

The `randombytes` module provides functions for getting random data.

```lua
local randombytes = require'luasodium.randombytes'

print(randombytes.randombytes_random()) -- prints a random number
```

#### Constants

* `randombytes.randombytes_SEEDBYTES` - required length of a seed string (32 bytes).

#### Functions

##### `number rand = randombytes.randombytes_random()`

Returns a random, unsigned 32-bit integer.

##### `number rand = randombytes.randombytes_uniform(number upper_bound)`

Returns a random, unsigned integer between 0 and the provided number (exclusive).

##### `string rand = randombytes.randombytes_buf(number length)`

Returns a string of random bytes - `length` is the length of the string to generate.

##### `string rand = randombytes.randombytes_buf_deterministic(number length, string seed)`

Returns a string of random bytes.

* `length` is the length of the string to generate.
* `seed` is a Lua string to use as a seed, must be 32 bytes long.

##### `boolean success = randombytes.randombytes_close()`

Deallocates global resources used by the pseudo-random number generator.

##### `randombytes.randombytes_stir()`

Reseeds the pseudo-random number generator.

### `luasodium.crypto_secretbox`

Wrapper for the `crypto_secretbox` functions.

#### Synopsis

```lua
local crypto_secretbox = require'luasodium.crypto_secretbox'

local message = 'my message to encrypto'
local nonce = string.rep('\0', crypto_secretbox.crypto_secretbox_NONCEBYTES)
local key = string.rep('\0', crypto_secretbox.crypto_secretbox_KEYBYTES)

assert(
  crypto_secretbox.crypto_secretbox_open_easy(
    crypto_secretbox.crypto_secretbox_easy(message,nonce,key),
    nonce,
    key
  ) == message
)
```

#### Constants

* `crypto_secretbox.crypto_secretbox_KEYBYTES` - valid key length
* `crypto_secretbox.crypto_secretbox_NONCEBYTES` - valid nonce length
* `crypto_secretbox.crypto_secretbox_MACBYTES` - valid MAC length

#### Functions

##### `string cipher = crypto_secretbox.crypto_secretbox_easy(string message, string nonce, string key)`

* Encrypts `message` using `nonce` and `key`.
* Returns the encrypted message.

##### `string message = crypto_secretbox.crypto_secretbox_open_easy(string cipher, string nonce, string key)`

* Decrypts `cipher` using `nonce` and `key`.
* Returns the plain-text message.

##### `string cipher, string mac = crypto_secretbox.crypto_secretbox_detached(string message, string nonce, string key)`

* Encrypts `message` using `nonce` and `key`.
* Returns the encrypted message and the MAC as separate strings.

##### `string message = crypto_secretbox.crypto_secretbox_open_detached(string cipher, string mac, string nonce, string key)`

* Decrypts `cipher` with `mac`, `nonce`, and `key`.
* Returns the plain-text message.

##### `string key = crypto_secretbox.crypto_secretbox_keygen()`

* Returns a random string that can be used as a key.


### `luasodium.crypto_box`

Wrapper for the `crypto_box` functions.

#### Synopsis

```lua
require('luasodium').init()
local crypto_box = require'luasodium.crypto_box'

local message = 'my message to encrypt'
local a_public_key, a_private_key = crypto_box.crypto_box_keypair()
local b_public_key, b_private_key = crypto_box.crypto_box_keypair()
local nonce = string.rep('\0', crypto_box.crypto_box_NONCEBYTES)

assert(
  crypto_box.crypto_box_open_easy(
    crypto_box.crypto_box_easy(message,nonce,b_public_key,a_private_key),
    nonce,
    a_public_key,b_private_key
  ) == message
)
```

#### Constants

* `crypto_box.crypto_box_PUBLICKEYBYTES` - valid public key length
* `crypto_box.crypto_box_SECRETKEYBYTES` - valid secret key length
* `crypto_box.crypto_box_MACBYTES` - valid MAC length
* `crypto_box.crypto_box_NONCEBYTES` - valid nonce length
* `crypto_box.crypto_box_SEEDBYTES` - valid seed length
* `crypto_box.crypto_box_BEFORENMBYTES`

#### Functions

##### `string public, string secret = crypto_box.crypto_box_keypair()`

* Returns a new public and secret pair of keys.

##### `string public, string secret = crypto_box.crypto_box_seed_keypair(string seed)`

* Returns a new public and secret pair of keys from a seed.

##### `string cipher = crypto_box.crypto_box_easy(string message, string nonce, string public_key, string private_key)`

* Encrypts `message` using the recipient's `public_key` and the signed with sender's `private_key`.
* Returns the encrypted message

##### `string message = crypto_box.crypto_box_open_easy(string cipher, string nonce, string public_key, string private_key)`

* Decrypts `cipher` using the sender's `public_key` and the  recipient's `private_key`.
* Returns the decrypted message

##### `string cipher, string mac = crypto_box.crypto_box_detached(string message, string nonce, string public_key, string private_key)`

* Encrypts `message` using the recipient's `public_key` and the signed with sender's `private_key`.
* Returns the encrypted message and the MAC.

##### `string message = crypto_box.crypto_box_open_detached(string cipher, string mac, string nonce, string public_key, string private_key)`

* Decrypts `cipher` using MAC, the sender's `public_key` and the with recipient's `private_key`.
* Returns the decrypted message

##### `string key = crypto_box.crypto_box_beforenm(string public_key, string private_key)`

* Returns a pre-computed key for encrypting messages in the following `_afternm` functions.

##### `string cipher = crypto_box.crypto_box_easy_afternm(string message, string nonce, string key)`

* Encrypts `message` using the pre-generated `key`.
* Returns the encrypted message

##### `string message = crypto_box.crypto_box_open_easy_afternm(string cipher, string nonce, string key)`

* Decrypts `cipher` using the pre-generated `key`.
* Returns the decrypted message

##### `string cipher, string mac = crypto_box.crypto_box_detached_afternm(string message, string nonce, string key)`

* Encrypts `message` using the pre-generated `key`.
* Returns the encrypted message and the MAC.

##### `string message = crypto_box.crypto_box_open_detached_afternm(string cipher, string mac, string nonce, string key)`

* Decrypts `cipher` using `mac` the pre-generated `key`.
* Returns the decrypted message

### `luasodium.crypto_scalarmult`

Wrapper for the `crypto_scalarmult` functions.

#### Constants

* `crypto_scalarmult.crypto_scalarmult_BYTES`
* `crypto_scalarmult.crypto_scalarmult_SCALARBYTES`

#### Functions

##### `string q = crypto_scalarmult.crypto_scalarmult_base(n)`

* Given a secret key `n`, returns the public key `q`

##### `string q = crypto_scalarmult.crypto_scalarmult(n,p)`

* Given a secret key `n` and public key `p`, returns the shared secret `q`.
