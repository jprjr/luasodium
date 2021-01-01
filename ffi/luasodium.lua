local M = {}

local crypto_auth        = require'luasodium.crypto_auth'
local crypto_box         = require'luasodium.crypto_box'
local crypto_secretbox   = require'luasodium.crypto_secretbox'
local crypto_sign        = require'luasodium.crypto_sign'
local crypto_scalarmult  = require'luasodium.crypto_scalarmult'
local randombytes        = require'luasodium.randombytes'
local utils              = require'luasodium.utils'
local version            = require'luasodium.version'

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
