local ok, mod

ok, mod = pcall(require,'luasodium.crypto_generichash.ffi')
if ok then
  return mod
end

ok, mod = pcall(require,'luasodium.crypto_generichash.core')
if ok then
  return mod
end

return require'luasodium.crypto_generichash.pureffi'



