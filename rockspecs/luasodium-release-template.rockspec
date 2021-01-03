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
    ["luasodium"] = "ffi/luasodium.lua",
    ["luasodium.crypto_auth"] = "lua/luasodium/crypto_auth.lua",
    ["luasodium.crypto_box"] = "lua/luasodium/crypto_box.lua",
    ["luasodium.crypto_hash"] = "lua/luasodium/crypto_hash.lua",
    ["luasodium.crypto_scalarmult"] = "lua/luasodium/crypto_scalarmult.lua",
    ["luasodium.crypto_secretbox"] = "lua/luasodium/crypto_secretbox.lua",
    ["luasodium.crypto_sign"] = "lua/luasodium/crypto_sign.lua",
    ["luasodium.crypto_stream"] = "lua/luasodium/crypto_stream.lua",
    ["luasodium.crypto_verify"] = "lua/luasodium/crypto_verify.lua",
    ["luasodium.randombytes"] = "lua/luasodium/randombytes.lua",
    ["luasodium.utils"] = "lua/luasodium/utils.lua",
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
    ["luasodium.crypto_hash.core"] = {
      sources = { "c/luasodium/crypto_hash/core.c" },
      libdirs = "$(SODIUM_LIBDIR)",
      incdirs = "$(SODIUM_INCDIR)",
      libraries = "sodium",
    },
    ["luasodium.crypto_hash.ffi"] = {
      sources = { "c/luasodium/crypto_hash/ffi.c" },
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
    ["luasodium.crypto_sign.core"] = {
      sources = { "c/luasodium/crypto_sign/core.c" },
      libdirs = "$(SODIUM_LIBDIR)",
      incdirs = "$(SODIUM_INCDIR)",
      libraries = "sodium",
    },
    ["luasodium.crypto_sign.ffi"] = {
      sources = { "c/luasodium/crypto_sign/ffi.c" },
      libdirs = "$(SODIUM_LIBDIR)",
      incdirs = "$(SODIUM_INCDIR)",
      libraries = "sodium",
    },
    ["luasodium.crypto_stream.core"] = {
      sources = { "c/luasodium/crypto_stream/core.c" },
      libdirs = "$(SODIUM_LIBDIR)",
      incdirs = "$(SODIUM_INCDIR)",
      libraries = "sodium",
    },
    ["luasodium.crypto_stream.ffi"] = {
      sources = { "c/luasodium/crypto_stream/ffi.c" },
      libdirs = "$(SODIUM_LIBDIR)",
      incdirs = "$(SODIUM_INCDIR)",
      libraries = "sodium",
    },
    ["luasodium.crypto_verify.core"] = {
      sources = { "c/luasodium/crypto_verify/core.c" },
      libdirs = "$(SODIUM_LIBDIR)",
      incdirs = "$(SODIUM_INCDIR)",
      libraries = "sodium",
    },
    ["luasodium.crypto_verify.ffi"] = {
      sources = { "c/luasodium/crypto_verify/ffi.c" },
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
