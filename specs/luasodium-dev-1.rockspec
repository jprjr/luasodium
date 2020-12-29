package = "luasodium"
version = "dev-1"

source = {
  url = "git://github.com/jprjr/luasodium.git"
}

description = {
  summary = "Lua bindings to libsodium, includes regular and FFI bindings",
  homepage = "https://github.com/jprjr/luasodium",
  license = "MIT"
}

build = {
  type = "builtin",
  modules = {
    ["luasodium.version.core"] = {
      sources = { "c/luasodium/version/core.c" },
    },
    ["luasodium.version.ffi"] = {
      sources = { "c/luasodium/version/ffi.c" },
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
    ["luasodium"] = "ffi/luasodium.lua",
    ["luasodium.core"] = "lua/luasodium/core.lua",
    ["luasodium.ffi"] = "lua/luasodium/ffi.lua",
    ["luasodium.utils"] = "lua/luasodium/utils.lua",
    ["luasodium.randombytes"] = "lua/luasodium/randombytes.lua",
    ["luasodium.crypto_secretbox"] = "lua/luasodium/crypto_secretbox.lua",
    ["luasodium.crypto_box"] = "lua/luasodium/crypto_box.lua",
    ["luasodium.crypto_scalarmult"] = "lua/luasodium/crypto_scalarmult.lua",
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
