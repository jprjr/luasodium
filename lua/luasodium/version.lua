local ok, lib = pcall(require,'luasodium.version.ffi')
if ok then return lib end

return require'luasodium.version.core'

