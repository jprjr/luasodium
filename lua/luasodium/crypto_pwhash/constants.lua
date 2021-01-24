local constant_keys = {
  'crypto_pwhash_ALG_ARGON2I13',
  'crypto_pwhash_ALG_ARGON2ID13',
  'crypto_pwhash_ALG_DEFAULT',
  'crypto_pwhash_BYTES_MAX',
  'crypto_pwhash_BYTES_MIN',
  'crypto_pwhash_MEMLIMIT_INTERACTIVE',
  'crypto_pwhash_MEMLIMIT_MAX',
  'crypto_pwhash_MEMLIMIT_MIN',
  'crypto_pwhash_MEMLIMIT_MODERATE',
  'crypto_pwhash_MEMLIMIT_SENSITIVE',
  'crypto_pwhash_OPSLIMIT_INTERACTIVE',
  'crypto_pwhash_OPSLIMIT_MAX',
  'crypto_pwhash_OPSLIMIT_MIN',
  'crypto_pwhash_OPSLIMIT_MODERATE',
  'crypto_pwhash_OPSLIMIT_SENSITIVE',
  'crypto_pwhash_PASSWD_MAX',
  'crypto_pwhash_PASSWD_MIN',
  'crypto_pwhash_SALTBYTES',
  'crypto_pwhash_STRBYTES',
  -- 'crypto_pwhash_STRPREFIX' -- handled in implementation since
  -- it's a string, and the constant loader assumes everything is
  -- a size_t
}

return constant_keys
