## Modules

Luasodium is broken into sub-modules, based on function prefixes in
the Libsodium API. For example, all the `randombytes` function are
in a `luasodium.randombytes` module.

There's a global `luasodium` module that includes all submodules,
you don't have to include each and every module.

Here's the completed modules:

* `luasodium.crypto_auth`: covers
    * ["Secret-key cryptography: Authentication"](https://libsodium.gitbook.io/doc/secret-key_cryptography/secret-key_authentication)
* `luasodium.crypto_box`: covers
    * ["Public-key cryptography: Authenticated encryption"](https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption)
* `luasodium.crypto_scalarmult`: covers
    * ["Advanced: Point*scalar multiplication"](https://libsodium.gitbook.io/doc/advanced/scalar_multiplication)
* `luasodium.crypto_secretbox`: covers
    * ["Secret-key cryptography: Authenticated encryption"](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox)
* `luasodium.utils`: covers
    * ["Usage"](https://libsodium.gitbook.io/doc/usage)
    * ["Helpers"](https://libsodium.gitbook.io/doc/helpers)
    * ["Padding"](https://libsodium.gitbook.io/doc/padding)
* `luasodium.randombytes`: covers
    * ["Generating Random Data"](https://libsodium.gitbook.io/doc/generating_random_data)


## Module Documentation


