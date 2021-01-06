local ok, mod

ok, mod = pcall(require,'luasodium.crypto_hash.ffi')
if ok then
  return mod
end

ok, mod = pcall(require,'luasodium.crypto_hash.core')
if ok then
  return mod
end

return require'luasodium.crypto_hash.pureffi'
