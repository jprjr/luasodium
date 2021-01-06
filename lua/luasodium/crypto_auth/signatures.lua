local signatures = {
  ['crypto_auth'] = [[
    int %s(unsigned char *out, const unsigned char *in,
           unsigned long long inlen, const unsigned char *k)
  ]],
  ['crypto_auth_verify'] = [[
    int %s(const unsigned char *h, const unsigned char *in,
           unsigned long long inlen, const unsigned char *k)
  ]],
  ['crypto_auth_keygen'] = [[
    void %s(unsigned char *k)
  ]],
}

return signatures

