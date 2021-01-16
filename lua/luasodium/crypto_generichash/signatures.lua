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

local crypto_generichash_init_sig = [[
  int (%s)(
  void *,
  const unsigned char *,
  const size_t, const size_t)
]]

local crypto_generichash_update_sig = [[
  int (%s)(
  void *,
  const unsigned char *,
  unsigned long long)
]]

local crypto_generichash_final_sig = [[
  int (%s)(
  void *,
  unsigned char *, const size_t)
]]

local signatures = {
  ['crypto_generichash_keygen'] = crypto_generichash_keygen_sig,
  ['crypto_generichash_statebytes'] = crypto_generichash_statebytes_sig,
  ['crypto_generichash'] = crypto_generichash_sig,
  ['crypto_generichash_init'] = crypto_generichash_init_sig,
  ['crypto_generichash_update'] = crypto_generichash_update_sig,
  ['crypto_generichash_final'] = crypto_generichash_final_sig,
}

return signatures
