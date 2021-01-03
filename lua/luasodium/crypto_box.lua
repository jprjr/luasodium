local ok, mod = pcall(require,'luasodium.crypto_box.ffi')
if ok then
  return mod
end

return require'luasodium.crypto_box.core'
