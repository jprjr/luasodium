local ok, lib = pcall(require,'luasodium.crypto_box.ffi')
if ok then return lib end

return require'luasodium.crypto_box.core'
