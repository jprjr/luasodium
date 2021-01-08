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
    ["luasodium.core"] = "lua/luasodium/core.lua",
    ["luasodium.ffi"] = "lua/luasodium/ffi.lua",
    ["luasodium.pureffi"] = "lua/luasodium/pureffi.lua",
    ["luasodium.crypto_auth"] = "lua/luasodium/crypto_auth.lua",
    ["luasodium.crypto_auth.constants"] = "lua/luasodium/crypto_auth/constants.lua",
    ["luasodium.crypto_auth.implementation"] = "lua/luasodium/crypto_auth/implementation.lua",
    ["luasodium.crypto_auth.pureffi"] = "lua/luasodium/crypto_auth/pureffi.lua",
    ["luasodium.crypto_auth.signatures"] = "lua/luasodium/crypto_auth/signatures.lua",
    ["luasodium.crypto_box"] = "lua/luasodium/crypto_box.lua",
    ["luasodium.crypto_box.constants"] = "lua/luasodium/crypto_box/constants.lua",
    ["luasodium.crypto_box.implementation"] = "lua/luasodium/crypto_box/implementation.lua",
    ["luasodium.crypto_box.pureffi"] = "lua/luasodium/crypto_box/pureffi.lua",
    ["luasodium.crypto_box.signatures"] = "lua/luasodium/crypto_box/signatures.lua",
    ["luasodium.crypto_hash"] = "lua/luasodium/crypto_hash.lua",
    ["luasodium.crypto_hash.constants"] = "lua/luasodium/crypto_hash/constants.lua",
    ["luasodium.crypto_hash.implementation"] = "lua/luasodium/crypto_hash/implementation.lua",
    ["luasodium.crypto_hash.pureffi"] = "lua/luasodium/crypto_hash/pureffi.lua",
    ["luasodium.crypto_hash.signatures"] = "lua/luasodium/crypto_hash/signatures.lua",
    ["luasodium.crypto_onetimeauth"] = "lua/luasodium/crypto_onetimeauth.lua",
    ["luasodium.crypto_onetimeauth.constants"] = "lua/luasodium/crypto_onetimeauth/constants.lua",
    ["luasodium.crypto_onetimeauth.implementation"] = "lua/luasodium/crypto_onetimeauth/implementation.lua",
    ["luasodium.crypto_onetimeauth.pureffi"] = "lua/luasodium/crypto_onetimeauth/pureffi.lua",
    ["luasodium.crypto_onetimeauth.signatures"] = "lua/luasodium/crypto_onetimeauth/signatures.lua",
    ["luasodium.crypto_scalarmult"] = "lua/luasodium/crypto_scalarmult.lua",
    ["luasodium.crypto_scalarmult.constants"] = "lua/luasodium/crypto_scalarmult/constants.lua",
    ["luasodium.crypto_scalarmult.implementation"] = "lua/luasodium/crypto_scalarmult/implementation.lua",
    ["luasodium.crypto_scalarmult.pureffi"] = "lua/luasodium/crypto_scalarmult/pureffi.lua",
    ["luasodium.crypto_scalarmult.signatures"] = "lua/luasodium/crypto_scalarmult/signatures.lua",
    ["luasodium.crypto_secretbox"] = "lua/luasodium/crypto_secretbox.lua",
    ["luasodium.crypto_secretbox.constants"] = "lua/luasodium/crypto_secretbox/constants.lua",
    ["luasodium.crypto_secretbox.implementation"] = "lua/luasodium/crypto_secretbox/implementation.lua",
    ["luasodium.crypto_secretbox.pureffi"] = "lua/luasodium/crypto_secretbox/pureffi.lua",
    ["luasodium.crypto_secretbox.signatures"] = "lua/luasodium/crypto_secretbox/signatures.lua",
    ["luasodium.crypto_sign"] = "lua/luasodium/crypto_sign.lua",
    ["luasodium.crypto_sign.constants"] = "lua/luasodium/crypto_sign/constants.lua",
    ["luasodium.crypto_sign.implementation"] = "lua/luasodium/crypto_sign/implementation.lua",
    ["luasodium.crypto_sign.pureffi"] = "lua/luasodium/crypto_sign/pureffi.lua",
    ["luasodium.crypto_sign.signatures"] = "lua/luasodium/crypto_sign/signatures.lua",
    ["luasodium.crypto_stream"] = "lua/luasodium/crypto_stream.lua",
    ["luasodium.crypto_stream.constants"] = "lua/luasodium/crypto_stream/constants.lua",
    ["luasodium.crypto_stream.implementation"] = "lua/luasodium/crypto_stream/implementation.lua",
    ["luasodium.crypto_stream.pureffi"] = "lua/luasodium/crypto_stream/pureffi.lua",
    ["luasodium.crypto_stream.signatures"] = "lua/luasodium/crypto_stream/signatures.lua",
    ["luasodium.crypto_verify"] = "lua/luasodium/crypto_verify.lua",
    ["luasodium.crypto_verify.constants"] = "lua/luasodium/crypto_verify/constants.lua",
    ["luasodium.crypto_verify.implementation"] = "lua/luasodium/crypto_verify/implementation.lua",
    ["luasodium.crypto_verify.pureffi"] = "lua/luasodium/crypto_verify/pureffi.lua",
    ["luasodium.crypto_verify.signatures"] = "lua/luasodium/crypto_verify/signatures.lua",
    ["luasodium.randombytes"] = "lua/luasodium/randombytes.lua",
    ["luasodium.randombytes.constants"] = "lua/luasodium/randombytes/constants.lua",
    ["luasodium.randombytes.implementation"] = "lua/luasodium/randombytes/implementation.lua",
    ["luasodium.randombytes.pureffi"] = "lua/luasodium/randombytes/pureffi.lua",
    ["luasodium.randombytes.signatures"] = "lua/luasodium/randombytes/signatures.lua",
    ["luasodium.utils"] = "lua/luasodium/utils.lua",
    ["luasodium.utils.constants"] = "lua/luasodium/utils/constants.lua",
    ["luasodium.utils.implementation"] = "lua/luasodium/utils/implementation.lua",
    ["luasodium.utils.pureffi"] = "lua/luasodium/utils/pureffi.lua",
    ["luasodium.utils.signatures"] = "lua/luasodium/utils/signatures.lua",
    ["luasodium.version"] = "lua/luasodium/version.lua",
    ["luasodium.version.constants"] = "lua/luasodium/version/constants.lua",
    ["luasodium.version.implementation"] = "lua/luasodium/version/implementation.lua",
    ["luasodium.version.pureffi"] = "lua/luasodium/version/pureffi.lua",
    ["luasodium.version.signatures"] = "lua/luasodium/version/signatures.lua",
    ["luasodium"] = {
      libdirs = "$(SODIUM_LIBDIR)",
      incdirs = "$(SODIUM_INCDIR)",
      libraries = "sodium",
      sources = {
        "c/luasodium/luasodium.c",
        "c/luasodium/crypto_auth/core.c",
        "c/luasodium/crypto_auth/ffi.c",
        "c/luasodium/crypto_box/core.c",
        "c/luasodium/crypto_box/ffi.c",
        "c/luasodium/crypto_hash/core.c",
        "c/luasodium/crypto_hash/ffi.c",
        "c/luasodium/crypto_onetimeauth/core.c",
        "c/luasodium/crypto_onetimeauth/ffi.c",
        "c/luasodium/crypto_scalarmult/core.c",
        "c/luasodium/crypto_scalarmult/ffi.c",
        "c/luasodium/crypto_secretbox/core.c",
        "c/luasodium/crypto_secretbox/ffi.c",
        "c/luasodium/crypto_sign/core.c",
        "c/luasodium/crypto_sign/ffi.c",
        "c/luasodium/crypto_stream/core.c",
        "c/luasodium/crypto_stream/ffi.c",
        "c/luasodium/crypto_verify/core.c",
        "c/luasodium/crypto_verify/ffi.c",
        "c/luasodium/randombytes/core.c",
        "c/luasodium/randombytes/ffi.c",
        "c/luasodium/utils/core.c",
        "c/luasodium/utils/ffi.c",
        "c/luasodium/version/core.c",
        "c/luasodium/version/ffi.c",
      },
    },
  }
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
