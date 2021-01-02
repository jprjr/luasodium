local constant_keys = {
  'crypto_sign_PUBLICKEYBYTES',
  'crypto_sign_SECRETKEYBYTES',
  'crypto_sign_BYTES',
  'crypto_sign_SEEDBYTES',
  'crypto_sign_STATEBYTES', -- not an actual const in libsodium,
                            -- but this way we use the usual code
                            -- to grab it
}

return constant_keys
