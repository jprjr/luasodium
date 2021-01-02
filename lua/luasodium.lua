local ok, lib = pcall(require,'luasodium.ffi')
if ok then
  return lib
end

return require'luasodium.core'
