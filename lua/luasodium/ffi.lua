local M = {}

local crypto_auth        = require'luasodium.crypto_auth.ffi'
local crypto_box         = require'luasodium.crypto_box.ffi'
local crypto_secretbox   = require'luasodium.crypto_secretbox.ffi'
local crypto_scalarmult  = require'luasodium.crypto_scalarmult.ffi'
local randombytes        = require'luasodium.randombytes.ffi'
local utils              = require'luasodium.utils.ffi'
local version            = require'luasodium.version.ffi'

local modules = {
  crypto_auth,
  crypto_box,
  crypto_scalarmult,
  crypto_secretbox,
  randombytes,
  utils,
  version,
}

for _,mod in ipairs(modules) do
  for k,v in pairs(mod) do
    M[k] = v
  end
end

return M


