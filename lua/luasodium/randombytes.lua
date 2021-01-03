local ok, mod = pcall(require,'luasodium.randombytes.ffi')
if ok then
  return mod
end

return require'luasodium.randombytes.core'
