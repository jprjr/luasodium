### `luasodium.crypto_auth`

Wrapper for the `crypto_auth` functions.

#### Synopsis

```lua
local crypto_auth = require'luasodium.crypto_auth'

local message = 'a message to authenticate'
local key = crypto_auth.crypto_auth_keygen()
local tag = crypto_auth.crypto_auth(message,key)
assert(crypto_auth.crypto_auth_verify(tag,message,key) == true)
```

#### Constants

* `crypto_auth.crypto_auth_BYTES`
* `crypto_auth.crypto_auth_KEYBYTES`

#### Functions

##### `string tag = crypto_auth.crypto_auth(string message, string key)`

Creates a new authentication `tag` from a given `message` and `key`.

##### `boolean success = crypto_auth.crypto_auth_verify(string tag, string message, string key)`

Returns `true` if `tag` is a valid tag for `message` and `key`.

##### `string key = crypto_auth.crypto_auth_keygen()`

Returns a new, random key.

