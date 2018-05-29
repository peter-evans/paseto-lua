package = "paseto"
version = "0.1.0-1"
source = {
   url = "https://github.com/peter-evans/paseto-lua/archive/v0.1.0.tar.gz",
   dir = "paseto-0.1.0"
}
description = {
   summary = "PASETO (Platform-Agnostic Security Tokens) for Lua",
   detailed = "PASETO (Platform-Agnostic SEcurity TOkens) is a specification and reference implementation for secure stateless tokens.",
   homepage = "http://github.com/peter-evans/paseto-lua",
   license = "MIT"
}
dependencies = {
   "lua >= 5.1",
   "luatweetnacl >= 0.5"
}
build = {
   type = "builtin",
   modules = {
      paseto = "paseto.lua"
   }
}
