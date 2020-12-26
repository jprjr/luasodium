do
  local ok, lib = pcall(require,'luasodium.randombytes.ffi')
  if ok then
    return lib
  end
end

return require'luasodium.randombytes.core'

