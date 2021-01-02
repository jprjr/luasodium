local signatures = {
  ['crypto_secretbox_keygen'] = [[
    void %s(unsigned char *k)
  ]],
  ['crypto_secretbox'] = [[
      int %s(unsigned char *c,
              const unsigned char *m,
              unsigned long long mlen,
              const unsigned char *n,
              const unsigned char *k)
  ]],
  ['crypto_secretbox_open'] = [[
      int %s(unsigned char *m,
              const unsigned char *c,
              unsigned long long clen,
              const unsigned char *n,
              const unsigned char *k)
  ]],
  ['crypto_secretbox_easy'] = [[
      int %s(unsigned char *c,
              const unsigned char *m,
              unsigned long long mlen,
              const unsigned char *n,
              const unsigned char *k)
  ]],
  ['crypto_secretbox_open_easy'] = [[
      int %s(unsigned char *m,
              const unsigned char *c,
              unsigned long long clen,
              const unsigned char *n,
              const unsigned char *k)
  ]],
  ['crypto_secretbox_detached'] = [[
    int %s(unsigned char *c,
            unsigned char *mac,
            const unsigned char *m,
            unsigned long long mlen,
            const unsigned char *n,
            const unsigned char *k)
  ]],
  ['crypto_secretbox_open_detached'] = [[
    int %s(unsigned char *m,
           const unsigned char *c,
           const unsigned char *mac,
           unsigned long long clen,
           const unsigned char *n,
           const unsigned char *k)
  ]],
}

return signatures
