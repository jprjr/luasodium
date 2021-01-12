local crypto_auth_sig = [[
  int %s(unsigned char *out, const unsigned char *in,
         unsigned long long inlen, const unsigned char *k)
]]

local crypto_auth_verify_sig = [[
  int %s(const unsigned char *h, const unsigned char *in,
         unsigned long long inlen, const unsigned char *k)
]]

local crypto_auth_keygen_sig = [[
  void %s(unsigned char *k)
]]

local signatures = {
  ['crypto_auth'] = crypto_auth_sig,
  ['crypto_auth_verify'] = crypto_auth_verify_sig,
  ['crypto_auth_keygen'] = crypto_auth_keygen_sig,
  ['crypto_auth_hmacsha256'] = crypto_auth_sig,
  ['crypto_auth_hmacsha256_verify'] = crypto_auth_verify_sig,
  ['crypto_auth_hmacsha256_keygen'] = crypto_auth_keygen_sig,
  ['crypto_auth_hmacsha512256'] = crypto_auth_sig,
  ['crypto_auth_hmacsha512256_verify'] = crypto_auth_verify_sig,
  ['crypto_auth_hmacsha512256_keygen'] = crypto_auth_keygen_sig,
  ['crypto_auth_hmacsha512'] = crypto_auth_sig,
  ['crypto_auth_hmacsha512_verify'] = crypto_auth_verify_sig,
  ['crypto_auth_hmacsha512_keygen'] = crypto_auth_keygen_sig,
}

return signatures

