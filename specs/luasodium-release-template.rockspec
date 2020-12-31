package = "luasodium"
version = "@VERSION@-1"

source = {
  url = "https://github.com/jprjr/luasodium/releases/download/v@VERSION@/luasodium-@VERSION@.tar.gz"
}

description = {
  summary = "Lua bindings to libsodium, includes regular and FFI bindings",
  homepage = "https://github.com/jprjr/luasodium",
  license = "MIT"
}

build = {
  type = "builtin",
  modules = {
    ["luasodium.crypto_auth.core"] = {
      sources = { "c/luasodium/crypto_auth/core.c" },
      libdirs = "$(SODIUM_LIBDIR)",
      incdirs = "$(SODIUM_INCDIR)",
      libraries = "sodium",
    },
    ["luasodium.crypto_auth.ffi"] = {
      sources = { "c/luasodium/crypto_auth/ffi.c" },
      libdirs = "$(SODIUM_LIBDIR)",
      incdirs = "$(SODIUM_INCDIR)",
      libraries = "sodium",
    },
    ["luasodium.crypto_box.core"] = {
      sources = { "c/luasodium/crypto_box/core.c" },
      libdirs = "$(SODIUM_LIBDIR)",
      incdirs = "$(SODIUM_INCDIR)",
      libraries = "sodium",
    },
    ["luasodium.crypto_box.ffi"] = {
      sources = { "c/luasodium/crypto_box/ffi.c" },
      libdirs = "$(SODIUM_LIBDIR)",
      incdirs = "$(SODIUM_INCDIR)",
      libraries = "sodium",
    },
    ["luasodium.crypto_scalarmult.core"] = {
      sources = { "c/luasodium/crypto_scalarmult/core.c" },
      libdirs = "$(SODIUM_LIBDIR)",
      incdirs = "$(SODIUM_INCDIR)",
      libraries = "sodium",
    },
    ["luasodium.crypto_scalarmult.ffi"] = {
      sources = { "c/luasodium/crypto_scalarmult/ffi.c" },
      libdirs = "$(SODIUM_LIBDIR)",
      incdirs = "$(SODIUM_INCDIR)",
      libraries = "sodium",
    },
    ["luasodium.crypto_secretbox.core"] = {
      sources = { "c/luasodium/crypto_secretbox/core.c" },
      libdirs = "$(SODIUM_LIBDIR)",
      incdirs = "$(SODIUM_INCDIR)",
      libraries = "sodium",
    },
    ["luasodium.crypto_secretbox.ffi"] = {
      sources = { "c/luasodium/crypto_secretbox/ffi.c" },
      libdirs = "$(SODIUM_LIBDIR)",
      incdirs = "$(SODIUM_INCDIR)",
      libraries = "sodium",
    },
    ["luasodium.randombytes.core"] = {
      sources = { "c/luasodium/randombytes/core.c" },
      libdirs = "$(SODIUM_LIBDIR)",
      incdirs = "$(SODIUM_INCDIR)",
      libraries = "sodium",
    },
    ["luasodium.randombytes.ffi"] = {
      sources = { "c/luasodium/randombytes/ffi.c" },
      libdirs = "$(SODIUM_LIBDIR)",
      incdirs = "$(SODIUM_INCDIR)",
      libraries = "sodium",
    },
    ["luasodium.utils.core"] = {
      sources = { "c/luasodium/utils/core.c" },
      libdirs = "$(SODIUM_LIBDIR)",
      incdirs = "$(SODIUM_INCDIR)",
      libraries = "sodium",
    },
    ["luasodium.utils.ffi"] = {
      sources = { "c/luasodium/utils/ffi.c" },
      libdirs = "$(SODIUM_LIBDIR)",
      incdirs = "$(SODIUM_INCDIR)",
      libraries = "sodium",
    },
    ["luasodium.version.core"] = {
      sources = { "c/luasodium/version/core.c" },
    },
    ["luasodium.version.ffi"] = {
      sources = { "c/luasodium/version/ffi.c" },
    },
    ["luasodium"] = "ffi/luasodium.lua",
    ["luasodium.core"] = "lua/luasodium/core.lua",
    ["luasodium.ffi"] = "lua/luasodium/ffi.lua",
    ["luasodium.crypto_auth"] = "lua/luasodium/crypto_auth.lua",
    ["luasodium.crypto_box"] = "lua/luasodium/crypto_box.lua",
    ["luasodium.crypto_scalarmult"] = "lua/luasodium/crypto_scalarmult.lua",
    ["luasodium.crypto_secretbox"] = "lua/luasodium/crypto_secretbox.lua",
    ["luasodium.randombytes"] = "lua/luasodium/randombytes.lua",
    ["luasodium.utils"] = "lua/luasodium/utils.lua",
  },
}

dependencies = {
  "lua >= 5.1",
}

external_dependencies = {
  SODIUM = {
    header = 'sodium.h',
    library = 'sodium',
  },
}
