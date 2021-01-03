local ok, mod = pcall(require,'luasodium.crypto_onetimeauth.ffi')
if ok then
  return mod
end

return require'luasodium.crypto_onetimeauth.core'

