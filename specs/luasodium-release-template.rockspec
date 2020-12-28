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
    ["luasodium.core"] = {
      sources = { "c/luasodium/core.c" },
      libdirs = "$(SODIUM_LIBDIR)",
      incdirs = "$(SODIUM_INCDIR)",
      libraries = "sodium",
    },
    ["luasodium.ffi"] = {
      sources = { "c/luasodium/ffi.c" },
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
    ["luasodium"] = "lua/luasodium.lua",
    ["luasodium.randombytes"] = "lua/luasodium/randombytes.lua",
    ["luasodium.crypto_secretbox"] = "lua/luasodium/crypto_secretbox.lua",
    ["luasodium.crypto_box"] = "lua/luasodium/crypto_box.lua",
    ["luasodium.version"] = "ffi/luasodium/version.lua",
  },
}

dependencies = {
  "lua >= 5.1"
}

external_dependencies = {
  SODIUM = {
    header = 'sodium.h',
    library = 'sodium',
  }
}
