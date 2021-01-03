local lib = require'luasodium.crypto_scalarmult'

do
  local n = string.rep('\0',lib.crypto_scalarmult_SCALARBYTES)
  local q = lib.crypto_scalarmult_base(n)
  assert(string.len(q) == lib.crypto_scalarmult_BYTES)
end

print('success')
