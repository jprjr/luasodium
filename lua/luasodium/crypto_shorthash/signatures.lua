local crypto_shorthash_keygen_sig = [[
void %s(unsigned char *)
]]

local crypto_shorthash_sig = [[
int %s(unsigned char *,
       const unsigned char *,
       unsigned long long,
       const unsigned char *)
]]

local signatures = {
  ['crypto_shorthash_keygen'] = crypto_shorthash_keygen_sig,
  ['crypto_shorthash'] = crypto_shorthash_sig,
  ['crypto_shorthash_siphashx24'] = crypto_shorthash_sig,
}

return signatures
