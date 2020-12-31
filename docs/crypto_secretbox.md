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


