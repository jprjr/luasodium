local ok, mod = pcall(require,'luasodium.utils.ffi')
if ok then
  return mod
end

return require'luasodium.utils.core'
