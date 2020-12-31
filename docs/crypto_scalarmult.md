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

