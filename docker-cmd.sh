#!/bin/bash

make LUADIR=/lua_install

luacheck --std max+busted paseto spec
busted --verbose --coverage
luacov paseto, spec
