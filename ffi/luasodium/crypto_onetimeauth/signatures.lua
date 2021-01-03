local signatures = {
  ['crypto_onetimeauth'] = [[
    int %s(unsigned char *out, const unsigned char *in,
                           unsigned long long inlen, const unsigned char *k)
  ]],

  ['crypto_onetimeauth_verify'] = [[
    int %s(const unsigned char *h, const unsigned char *in,
           unsigned long long inlen, const unsigned char *k)
  ]],

  ['crypto_onetimeauth_init'] = [[
  int %s(void *state,
         const unsigned char *key)
  ]],

  ['crypto_onetimeauth_update'] = [[
  int %s(void *state,
         const unsigned char *in,
         unsigned long long inlen)
  ]],

  ['crypto_onetimeauth_final'] = [[
  int %s(void *state,
         unsigned char *out)

  ]],

  ['crypto_onetimeauth_statebytes'] = [[
    size_t %s(void)
  ]],
}

return signatures
