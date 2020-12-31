local ok, lib = pcall(require,'luasodium.crypto_auth.ffi')
if ok then return lib end

return require'luasodium.crypto_auth.core'

