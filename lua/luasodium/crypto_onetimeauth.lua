local ok, mod

ok, mod = pcall(require,'luasodium.crypto_onetimeauth.ffi')
if ok then
  return mod
end

ok, mod = pcall(require,'luasodium.crypto_onetimeauth.core')
if ok then
  return mod
end

return require'luasodium.crypto_onetimeauth.pureffi'

