local ok, mod = pcall(require,'luasodium.crypto_auth.ffi')
if ok then
  return mod
end

return require'luasodium.crypto_auth.core'
