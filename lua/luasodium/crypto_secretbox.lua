local ok, lib = pcall(require,'luasodium.crypto_secretbox.ffi')
if ok then return lib end

return require'luasodium.crypto_secretbox.core'
