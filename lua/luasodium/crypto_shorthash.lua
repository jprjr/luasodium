local ok, mod

ok, mod = pcall(require,'luasodium.crypto_shorthash.ffi')
if ok then
  return mod
end

ok, mod = pcall(require,'luasodium.crypto_shorthash.core')
if ok then
  return mod
end

return require'luasodium.crypto_shorthash.pureffi'

