local crypto_stream_sig = [[
  int (%s)(unsigned char *c, unsigned long long clen,
           const unsigned char *n, const unsigned char *k)
]]

local crypto_stream_xor_sig = [[
  int (%s)(unsigned char *c, const unsigned char *m,
           unsigned long long mlen,
           const unsigned char *n, const unsigned char *k)
]]

local crypto_stream_xor_ic_sig = [[
  int (%s)(unsigned char *c, const unsigned char *m,
           unsigned long long mlen,
           const unsigned char *n, uint64_t ic,
           const unsigned char *k)
]]

local crypto_stream_xor_ic32_sig = [[
  int (%s)(unsigned char *c, const unsigned char *m,
           unsigned long long mlen,
           const unsigned char *n, uint32_t ic,
           const unsigned char *k)
]]

local crypto_stream_keygen_sig = [[
  void (%s)(unsigned char *k)
]]

local signatures = {
  ['crypto_stream'] = crypto_stream_sig,
  ['crypto_stream_xor'] = crypto_stream_xor_sig,
  ['crypto_stream_keygen'] = crypto_stream_keygen_sig,
  ['crypto_stream_xsalsa20'] = crypto_stream_sig,
  ['crypto_stream_xsalsa20_xor'] = crypto_stream_xor_sig,
  ['crypto_stream_xsalsa20_xor_ic'] = crypto_stream_xor_ic_sig,
  ['crypto_stream_xsalsa20_keygen'] = crypto_stream_keygen_sig,
  ['crypto_stream_salsa20'] = crypto_stream_sig,
  ['crypto_stream_salsa20_xor'] = crypto_stream_xor_sig,
  ['crypto_stream_salsa20_xor_ic'] = crypto_stream_xor_ic_sig,
  ['crypto_stream_salsa20_keygen'] = crypto_stream_keygen_sig,
  ['crypto_stream_salsa2012'] = crypto_stream_sig,
  ['crypto_stream_salsa2012_xor'] = crypto_stream_xor_sig,
  ['crypto_stream_salsa2012_keygen'] = crypto_stream_keygen_sig,
  ['crypto_stream_salsa208'] = crypto_stream_sig,
  ['crypto_stream_salsa208_xor'] = crypto_stream_xor_sig,
  ['crypto_stream_salsa208_keygen'] = crypto_stream_keygen_sig,
  ['crypto_stream_xchacha20'] = crypto_stream_sig,
  ['crypto_stream_xchacha20_xor'] = crypto_stream_xor_sig,
  ['crypto_stream_xchacha20_xor_ic'] = crypto_stream_xor_ic_sig,
  ['crypto_stream_xchacha20_keygen'] = crypto_stream_keygen_sig,
  ['crypto_stream_chacha20'] = crypto_stream_sig,
  ['crypto_stream_chacha20_xor'] = crypto_stream_xor_sig,
  ['crypto_stream_chacha20_xor_ic'] = crypto_stream_xor_ic_sig,
  ['crypto_stream_chacha20_keygen'] = crypto_stream_keygen_sig,
  ['crypto_stream_chacha20_ietf'] = crypto_stream_sig,
  ['crypto_stream_chacha20_ietf_xor'] = crypto_stream_xor_sig,
  ['crypto_stream_chacha20_ietf_xor_ic'] = crypto_stream_xor_ic32_sig,
  ['crypto_stream_chacha20_ietf_keygen'] = crypto_stream_keygen_sig,
}

return signatures
