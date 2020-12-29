local ok, lib = pcall(require,'luasodium.utils.ffi')
if ok then return lib end

return require'luasodium.utils.core'

