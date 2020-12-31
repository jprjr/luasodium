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

