local ok, lib = pcall(require,'luasodium.crypto_verify.ffi')
if ok then return lib end

return require'luasodium.crypto_verify.core'
