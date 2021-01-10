local crypto_onetimeauth_sig = [[
  int %s(unsigned char *out, const unsigned char *in,
         unsigned long long inlen, const unsigned char *k)
]]

local crypto_onetimeauth_verify_sig = [[
  int %s(const unsigned char *h, const unsigned char *in,
         unsigned long long inlen, const unsigned char *k)

]]

local crypto_onetimeauth_init_sig = [[
  int %s(void *state,
         const unsigned char *key)

]]

local crypto_onetimeauth_update_sig = [[
  int %s(void *state,
         const unsigned char *in,
         unsigned long long inlen)

]]

local crypto_onetimeauth_final_sig = [[
  int %s(void *state,
         unsigned char *out)
]]

local crypto_onetimeauth_keygen_sig = [[
  void %s(unsigned char *out)
]]

local crypto_onetimeauth_statebytes_sig = [[
    size_t %s(void)
]]

local signatures = {
  ['crypto_onetimeauth'] = crypto_onetimeauth_sig,
  ['crypto_onetimeauth_verify'] = crypto_onetimeauth_verify_sig,
  ['crypto_onetimeauth_init'] = crypto_onetimeauth_init_sig,
  ['crypto_onetimeauth_update'] = crypto_onetimeauth_update_sig,
  ['crypto_onetimeauth_final'] = crypto_onetimeauth_final_sig,
  ['crypto_onetimeauth_keygen'] = crypto_onetimeauth_keygen_sig,
  ['crypto_onetimeauth_statebytes'] = crypto_onetimeauth_statebytes_sig,
  ['crypto_onetimeauth_poly1305'] = crypto_onetimeauth_sig,
  ['crypto_onetimeauth_poly1305_verify'] = crypto_onetimeauth_verify_sig,
  ['crypto_onetimeauth_poly1305_init'] = crypto_onetimeauth_init_sig,
  ['crypto_onetimeauth_poly1305_update'] = crypto_onetimeauth_update_sig,
  ['crypto_onetimeauth_poly1305_final'] = crypto_onetimeauth_final_sig,
  ['crypto_onetimeauth_poly1305_keygen'] = crypto_onetimeauth_keygen_sig,
  ['crypto_onetimeauth_poly1305_statebytes'] = crypto_onetimeauth_statebytes_sig,
}

return signatures
