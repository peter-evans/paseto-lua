./lua_install/bin/luacheck --std max+busted *.lua spec
./lua_install/bin/busted --verbose --coverage
./lua_install/bin/luacov spec, paseto.lua