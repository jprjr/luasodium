local signatures = {
  ['crypto_box_keypair'] = [[
    int %s(unsigned char *pk, unsigned char *sk)
  ]],
  ['crypto_box_seed_keypair'] = [[
    int %s(unsigned char *pk, unsigned char *sk,
           const unsigned char *seed)
  ]],
  ['crypto_box'] = [[
      int %s(unsigned char *c, const unsigned char *m,
             unsigned long long mlen, const unsigned char *n,
             const unsigned char *pk, const unsigned char *sk)
  ]],
  ['crypto_box_open'] = [[
      int %s(unsigned char *m, const unsigned char *c,
             unsigned long long clen, const unsigned char *n,
             const unsigned char *pk, const unsigned char *sk)
  ]],
  ['crypto_box_afternm'] = [[
      int %s(unsigned char *c, const unsigned char *m,
             unsigned long long mlen, const unsigned char *n,
             const unsigned char *k)
  ]],
  ['crypto_box_open_afternm'] = [[
      int %s(unsigned char *m, const unsigned char *c,
             unsigned long long clen, const unsigned char *n,
             const unsigned char *p)
  ]],
  ['crypto_box_easy'] = [[
      int %s(unsigned char *c, const unsigned char *m,
             unsigned long long mlen, const unsigned char *n,
             const unsigned char *pk, const unsigned char *sk)
  ]],
  ['crypto_box_open_easy'] = [[
      int %s(unsigned char *m, const unsigned char *c,
             unsigned long long clen, const unsigned char *n,
             const unsigned char *pk, const unsigned char *sk)
  ]],
  ['crypto_box_detached'] = [[
      int %s(unsigned char *c, unsigned char *mac,
             const unsigned char *m,
             unsigned long long mlen,
             const unsigned char *n,
             const unsigned char *pk,
             const unsigned char *sk)
  ]],
  ['crypto_box_open_detached'] = [[
      int %s(unsigned char *m,
             const unsigned char *c,
             const unsigned char *mac,
             unsigned long long clen,
             const unsigned char *n,
             const unsigned char *pk,
             const unsigned char *sk)
  ]],
  ['crypto_box_beforenm'] = [[
      int %s(unsigned char *k, const unsigned char *pk,
             const unsigned char *sk)
  ]],
  ['crypto_box_easy_afternm'] = [[
      int %s(unsigned char *c, const unsigned char *m,
             unsigned long long mlen, const unsigned char *n,
             const unsigned char *k)
  ]],
  ['crypto_box_open_easy_afternm'] = [[
      int %s(unsigned char *m, const unsigned char *c,
             unsigned long long clen, const unsigned char *n,
             const unsigned char *k)
  ]],
  ['crypto_box_detached_afternm'] = [[
      int %s(unsigned char *c, unsigned char *mac,
             const unsigned char *m, unsigned long long mlen,
             const unsigned char *n, const unsigned char *k)
  ]],
  ['crypto_box_open_detached_afternm'] = [[
      int %s(unsigned char *m, const unsigned char *c,
             const unsigned char *mac,
             unsigned long long clen, const unsigned char *n,
             const unsigned char *k)
  ]],
}

return signatures
