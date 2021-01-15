local crypto_generichash_keygen_sig = [[
  void %s(unsigned char *)
]]

local crypto_generichash_statebytes_sig = [[
  size_t %s(void)
]]

local crypto_generichash_sig = [[
  int (%s)(
  unsigned char *, size_t ,
  const unsigned char *, unsigned long long,
  const unsigned char *, size_t)
]]

local signatures = {
  ['crypto_generichash_keygen'] = crypto_generichash_keygen_sig,
  ['crypto_generichash_statebytes'] = crypto_generichash_statebytes_sig,
  ['crypto_generichash'] = crypto_generichash_sig,
}

return signatures
