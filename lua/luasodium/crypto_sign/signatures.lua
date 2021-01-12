local crypto_sign_keypair_sig = [[
  int %s(unsigned char *pk, unsigned char *sk)
]]

local crypto_sign_seed_keypair_sig = [[
  int %s(unsigned char *pk, unsigned char *sk,
         const unsigned char *seed)
]]

local crypto_sign_sig = [[
  int %s(unsigned char *sm, unsigned long long *smlen_p,
         const unsigned char *m, unsigned long long mlen,
         const unsigned char *sk)
]]

local crypto_sign_open_sig = [[
  int %s(unsigned char *m, unsigned long long *mlen_p,
         const unsigned char *sm, unsigned long long smlen,
         const unsigned char *pk)
]]

local crypto_sign_detached_sig = [[
  int %s(unsigned char *sig, unsigned long long *siglen_p,
         const unsigned char *m, unsigned long long mlen,
         const unsigned char *sk)
]]

local crypto_sign_verify_detached_sig = [[
  int %s(const unsigned char *sig, const unsigned char *m,
         unsigned long long mlen, const unsigned char *pk)
]]

local crypto_sign_sk_to_seed_sig = [[
  int %s(unsigned char *seed, const unsigned char *sk)
]]

local crypto_sign_sk_to_pk_sig = [[
  int %s(unsigned char *pk, const unsigned char *sk)
]]

local crypto_sign_init_sig = [[
  int %s(void *state)
]]

local crypto_sign_update_sig = [[
  int %s(void *state, const unsigned char *m, unsigned long long mlen)
]]

local crypto_sign_final_create_sig = [[
  int %s(void *state, unsigned char *sig,
         unsigned long long *siglen_p, const unsigned char *sk)
]]

local crypto_sign_final_verify_sig = [[
  int %s(void *state, const unsigned char *sig,
         const unsigned char *pk)
]]

local crypto_sign_statebytes_sig = [[
  size_t %s(void)
]]

local signatures = {
  ['crypto_sign_keypair'] = crypto_sign_keypair_sig,
  ['crypto_sign_seed_keypair'] = crypto_sign_seed_keypair_sig,
  ['crypto_sign'] = crypto_sign_sig,
  ['crypto_sign_open'] = crypto_sign_open_sig,
  ['crypto_sign_detached'] = crypto_sign_detached_sig,
  ['crypto_sign_verify_detached'] = crypto_sign_verify_detached_sig,
  ['crypto_sign_init'] = crypto_sign_init_sig,
  ['crypto_sign_update'] = crypto_sign_update_sig,
  ['crypto_sign_final_create'] = crypto_sign_final_create_sig,
  ['crypto_sign_final_verify'] = crypto_sign_final_verify_sig,
  ['crypto_sign_statebytes'] = crypto_sign_statebytes_sig,

  ['crypto_sign_ed25519_keypair'] = crypto_sign_keypair_sig,
  ['crypto_sign_ed25519_seed_keypair'] = crypto_sign_seed_keypair_sig,
  ['crypto_sign_ed25519'] = crypto_sign_sig,
  ['crypto_sign_ed25519_open'] = crypto_sign_open_sig,
  ['crypto_sign_ed25519_detached'] = crypto_sign_detached_sig,
  ['crypto_sign_ed25519_verify_detached'] = crypto_sign_verify_detached_sig,

  ['crypto_sign_ed25519_sk_to_seed'] = crypto_sign_sk_to_seed_sig,
  ['crypto_sign_ed25519_sk_to_pk'] = crypto_sign_sk_to_pk_sig,

  ['crypto_sign_ed25519ph_init'] = crypto_sign_init_sig,
  ['crypto_sign_ed25519ph_update'] = crypto_sign_update_sig,
  ['crypto_sign_ed25519ph_final_create'] = crypto_sign_final_create_sig,
  ['crypto_sign_ed25519ph_final_verify'] = crypto_sign_final_verify_sig,
  ['crypto_sign_ed25519ph_statebytes'] = crypto_sign_statebytes_sig,

}

return signatures


