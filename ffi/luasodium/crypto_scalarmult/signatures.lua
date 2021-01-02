local signatures = {
  ['crypto_scalarmult_base'] = [[
    int %s(unsigned char *q, const unsigned char *n)
  ]],
  ['crypto_scalarmult'] = [[
    int %s(unsigned char *q, const unsigned char *n,
           const unsigned char *p)
  ]],
}

return signatures
