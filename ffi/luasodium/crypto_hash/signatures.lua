local signatures = {
  ['crypto_hash'] = [[
    int %s(unsigned char *out, const unsigned char *in,
           unsigned long long inlen)
  ]],
  ['crypto_hash_sha256'] = [[
    int %s(unsigned char *out, const unsigned char *in,
           unsigned long long inlen)
  ]],
  ['crypto_hash_sha512'] = [[
    int %s(unsigned char *out, const unsigned char *in,
           unsigned long long inlen)
  ]],
  ['crypto_hash_sha256_init'] = [[
    int %s(void *state)
  ]],
  ['crypto_hash_sha256_update'] = [[
    int %s(void *state, const unsigned char *m, unsigned long long mlen)
  ]],
  ['crypto_hash_sha256_final'] = [[
    int %s(void *state, unsigned char *h)
  ]],
  ['crypto_hash_sha512_init'] = [[
    int %s(void *state)
  ]],
  ['crypto_hash_sha512_update'] = [[
    int %s(void *state, const unsigned char *m, unsigned long long mlen)
  ]],
  ['crypto_hash_sha512_final'] = [[
    int %s(void *state, unsigned char *h)
  ]],
}

return signatures
