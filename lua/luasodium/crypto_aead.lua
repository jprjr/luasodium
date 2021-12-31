local ok, mod

ok, mod = pcall(require,'luasodium.crypto_aead.ffi')
if ok then
  return mod
end

ok, mod = pcall(require,'luasodium.crypto_aead.core')
if ok then
  return mod
end

return require'luasodium.crypto_aead.pureffi'
