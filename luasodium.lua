do
  local ok, lib = pcall(require,'luasodium.ffi')
  if ok then
    print('using ffi')
    return lib
  end
end

return require'luasodium.core'
