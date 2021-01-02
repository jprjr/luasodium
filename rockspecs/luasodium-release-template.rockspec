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
