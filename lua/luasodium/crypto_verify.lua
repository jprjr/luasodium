local ok, mod

ok, mod = pcall(require,'luasodium.crypto_verify.ffi')
if ok then
  return mod
end

ok, mod = pcall(require,'luasodium.crypto_verify.core')
if ok then
  return mod
end

return require'luasodium.crypto_verify.pureffi'
