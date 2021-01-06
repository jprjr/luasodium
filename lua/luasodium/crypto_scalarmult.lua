local ok, mod

ok, mod = pcall(require,'luasodium.crypto_scalarmult.ffi')
if ok then
  return mod
end

ok, mod = pcall(require,'luasodium.crypto_scalarmult.core')
if ok then
  return mod
end

return require'luasodium.crypto_scalarmult.pureffi'
