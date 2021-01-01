local M = {}

local crypto_auth        = require'luasodium.crypto_auth.core'
local crypto_box         = require'luasodium.crypto_box.core'
local crypto_scalarmult  = require'luasodium.crypto_scalarmult.core'
local crypto_secretbox   = require'luasodium.crypto_secretbox.core'
local crypto_sign        = require'luasodium.crypto_sign.core'
local randombytes        = require'luasodium.randombytes.core'
local utils              = require'luasodium.utils.core'
local version            = require'luasodium.version.core'

local modules = {
  crypto_auth,
  crypto_box,
  crypto_scalarmult,
  crypto_secretbox,
  crypto_sign,
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

