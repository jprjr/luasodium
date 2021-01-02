local implementation = require'luasodium.crypto_hash.implementation'
local constant_keys = require'luasodium.crypto_hash.constants'
local signatures = require'luasodium.crypto_hash.signatures'

local lib_loader = require'luasodium._ffi.lib_loader'
local constant_loader = require'luasodium._ffi.constant_loader'
local default_signatures = require'luasodium._ffi.default_signatures'

default_signatures(signatures)

local libs = lib_loader(signatures)
local constants = constant_loader(libs.sodium,constant_keys)

return implementation(libs,constants)

