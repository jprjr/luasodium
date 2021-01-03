local ok, mod = pcall(require,'luasodium.crypto_sign.ffi')
if ok then
  return mod
end

return require'luasodium.crypto_sign.core'
