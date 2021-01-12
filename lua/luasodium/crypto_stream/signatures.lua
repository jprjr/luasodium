local crypto_stream_sig = [[
  int (%s)(unsigned char *c, unsigned long long clen,
           const unsigned char *n, const unsigned char *k)
]]

local crypto_stream_xor_sig = [[
  int (%s)(unsigned char *c, const unsigned char *m,
           unsigned long long mlen,
           const unsigned char *n, const unsigned char *k)
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
  ['crypto_stream_xsalsa20_keygen'] = crypto_stream_keygen_sig,
  ['crypto_stream_salsa20'] = crypto_stream_sig,
  ['crypto_stream_salsa20_xor'] = crypto_stream_xor_sig,
  ['crypto_stream_salsa20_keygen'] = crypto_stream_keygen_sig,
  ['crypto_stream_salsa2012'] = crypto_stream_sig,
  ['crypto_stream_salsa2012_xor'] = crypto_stream_xor_sig,
  ['crypto_stream_salsa2012_keygen'] = crypto_stream_keygen_sig,
}

return signatures
