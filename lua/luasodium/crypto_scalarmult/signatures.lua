local crypto_scalarmult_base_sig = [[
  int %s(unsigned char *q, const unsigned char *n)
]]

local crypto_scalarmult_sig = [[
  int %s(unsigned char *q, const unsigned char *n,
         const unsigned char *p)
]]

local signatures = {
  ['crypto_scalarmult_base'] = crypto_scalarmult_base_sig,
  ['crypto_scalarmult'] = crypto_scalarmult_sig,
  ['crypto_scalarmult_curve25519_base'] = crypto_scalarmult_base_sig,
  ['crypto_scalarmult_curve25519'] = crypto_scalarmult_sig,
}

return signatures
