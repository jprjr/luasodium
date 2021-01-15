local crypto_generichash_keygen_sig = [[
  void %s(unsigned char *)
]]

local crypto_generichash_statebytes_sig = [[
  size_t %s(void)
]]

local signatures = {
  ['crypto_generichash_keygen'] = crypto_generichash_keygen_sig,
  ['crypto_generichash_statebytes'] = crypto_generichash_statebytes_sig,
}

return signatures
