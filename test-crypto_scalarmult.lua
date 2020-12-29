local lib = require'luasodium.crypto_scalarmult'

if jit then
  assert(lib == require'luasodium.crypto_scalarmult.ffi')
end

do
  local n = string.rep('\0',lib.crypto_scalarmult_SCALARBYTES)
  local q = lib.crypto_scalarmult_base(n)
  assert(string.len(q) == lib.crypto_scalarmult_BYTES)
end

print('success')
