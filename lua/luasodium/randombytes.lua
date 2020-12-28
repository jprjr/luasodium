local ok, lib = pcall(require,'luasodium.randombytes.ffi')
if ok then return lib end

return require'luasodium.randombytes.core'
