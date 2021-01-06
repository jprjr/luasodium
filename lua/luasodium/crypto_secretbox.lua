local ok, mod

ok, mod = pcall(require,'luasodium.crypto_secretbox.ffi')
if ok then
  return mod
end

ok, mod = pcall(require,'luasodium.crypto_secretbox.core')
if ok then
  return mod
end

return require'luasodium.crypto_secretbox.pureffi'
