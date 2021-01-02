local signatures = {
  ['crypto_sign_keypair'] = [[
    int %s(unsigned char *pk, unsigned char *sk)

  ]],
  ['crypto_sign_seed_keypair'] = [[
    int %s(unsigned char *pk, unsigned char *sk,
           const unsigned char *seed)
  ]],
  ['crypto_sign'] = [[
    int %s(unsigned char *sm, unsigned long long *smlen_p,
           const unsigned char *m, unsigned long long mlen,
           const unsigned char *sk)
  ]],
  ['crypto_sign_open'] = [[
  int %s(unsigned char *m, unsigned long long *mlen_p,
         const unsigned char *sm, unsigned long long smlen,
         const unsigned char *pk)
  ]],
  ['crypto_sign_detached'] = [[
  int %s(unsigned char *sig, unsigned long long *siglen_p,
         const unsigned char *m, unsigned long long mlen,
         const unsigned char *sk)
  ]],
  ['crypto_sign_verify_detached'] = [[
    int %s(const unsigned char *sig, const unsigned char *m,
           unsigned long long mlen, const unsigned char *pk)
  ]],
  ['crypto_sign_init'] = [[
    int %s(void *state)
  ]],
  ['crypto_sign_update'] = [[
    int %s(void *state, const unsigned char *m, unsigned long long mlen)
  ]],
  ['crypto_sign_final_create'] = [[
    int %s(void *state, unsigned char *sig,
           unsigned long long *siglen_p, const unsigned char *sk)
  ]],
  ['crypto_sign_final_verify'] = [[
    int %s(void *state, const unsigned char *sig,
           const unsigned char *pk)
  ]],
  ['crypto_sign_ed25519_sk_to_seed'] = [[
    int %s(unsigned char *seed, const unsigned char *sk)
  ]],
  ['crypto_sign_ed25519_sk_to_pk'] = [[
    int %s(unsigned char *pk, const unsigned char *sk)
  ]],
}

return signatures


