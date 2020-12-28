do
    require('luasodium').init()
end

local crypto_scalarmult = require'luasodium.crypto_scalarmult'

if jit then
  assert(crypto_scalarmult == require'luasodium.crypto_scalarmult.ffi')
end

do
  local n = string.rep('\0',crypto_scalarmult.SCALARBYTES)
  local q = crypto_scalarmult.base(n)
  assert(string.len(q) == crypto_scalarmult.BYTES)
end

print('success')
