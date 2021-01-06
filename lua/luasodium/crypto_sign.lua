local ok, mod

ok, mod = pcall(require,'luasodium.crypto_sign.ffi')
if ok then
  return mod
end

ok, mod = pcall(require,'luasodium.crypto_sign.core')
if ok then
  return mod
end

return require'luasodium.crypto_sign.pureffi'
