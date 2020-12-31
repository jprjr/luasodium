### `luasodium.crypto_box`

Wrapper for the `crypto_box` functions.

#### Synopsis

```lua
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


