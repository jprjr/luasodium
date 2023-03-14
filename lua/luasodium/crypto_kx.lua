local ok, mod

ok, mod = pcall(require,'luasodium.crypto_kx.ffi')
if ok then
  return mod
end

ok, mod = pcall(require,'luasodium.crypto_kx.core')
if ok then
  return mod
end

return require'luasodium.crypto_kx.pureffi'

