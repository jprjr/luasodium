return {
  'crypto_hash_BYTES',
  'crypto_hash_sha256_BYTES',
  'crypto_hash_sha512_BYTES',
  'crypto_hash_sha256_STATEBYTES', -- not an actual const in libsodium,
                                   -- but this way we use the usual code
                                   -- to grab it
  'crypto_hash_sha512_STATEBYTES', -- not an actual const in libsodium
}
