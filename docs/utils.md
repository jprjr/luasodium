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

