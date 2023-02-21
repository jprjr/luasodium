local ffi = require'ffi'

return function(modname,pointers,constant_ptrs)
  local implementation = require('luasodium.' .. modname .. '.implementation')
  local signatures     = require('luasodium.' .. modname .. '.signatures')

  local function_loader = require'luasodium._ffi.function_loader'
  local default_signatures = require'luasodium._ffi.default_signatures'

  default_signatures(signatures)

  local constants = {}
  for k,t in pairs(constant_ptrs) do
    local f = t.func
    if t['type'] == 0 then
        constants[k] = tonumber((ffi.cast('int (*)(void)',f))())
    elseif t['type'] == 1 then
        constants[k] = tonumber((ffi.cast('size_t (*)(void)',f))())
    elseif t['type'] == 2 then
        constants[k] = ffi.string((ffi.cast('const char * (*)(void)',f))())
    end
  end

  return implementation(function_loader(signatures,pointers),constants)
end


