local ok, lib = pcall(require,'luasodium.crypto_scalarmult.ffi')
if ok then return lib end

return require'luasodium.crypto_scalarmult.core'

