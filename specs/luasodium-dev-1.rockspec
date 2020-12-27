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
    ["luasodium"] = "luasodium.c",
    ["luasodium.randombytes"] = "luasodium/randombytes.c",
    ["luasodium.crypto_secretbox"] = "luasodium/crypto_secretbox.c",
  }
}

dependencies = {
  "lua >= 5.1"
}

external_dependencies = {
  SODIUM = {
    library = 'sodium'
  }
}
