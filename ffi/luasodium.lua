local M = {}

local version           = require'luasodium.version'
local utils             = require'luasodium.utils'
local crypto_secretbox  = require'luasodium.crypto_secretbox'
local crypto_box        = require'luasodium.crypto_box'
local crypto_scalarmult = require'luasodium.crypto_scalarmult'
local randombytes = require'luasodium.randombytes'

local modules = {
  version,
  utils,
  crypto_secretbox,
  crypto_box,
  crypto_scalarmult,
  randombytes,
}

for _,mod in ipairs(modules) do
  for k,v in pairs(mod) do
    M[k] = v
  end
end

return M
