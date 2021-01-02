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
}

return signatures
