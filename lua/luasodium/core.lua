local M = {}

local version           = require'luasodium.version.core'
local utils             = require'luasodium.utils.core'
local crypto_secretbox  = require'luasodium.crypto_secretbox.core'
local crypto_box        = require'luasodium.crypto_box.core'
local crypto_scalarmult = require'luasodium.crypto_scalarmult.core'
local randombytes = require'luasodium.randombytes.core'

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

