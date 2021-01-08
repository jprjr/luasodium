return function(modname,pointers,constants)
  local implementation = require('luasodium.' .. modname .. '.implementation')
  local signatures     = require('luasodium.' .. modname .. '.signatures')

  local function_loader = require'luasodium._ffi.function_loader'
  local default_signatures = require'luasodium._ffi.default_signatures'

  default_signatures(signatures)

  return implementation(function_loader(signatures,pointers),constants)
end


