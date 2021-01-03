local sig = [[
int %s(unsigned const char *x, unsigned const char *y)
]]

local signatures = {
  ['crypto_verify_16'] = sig,
  ['crypto_verify_32'] = sig,
}

return signatures
