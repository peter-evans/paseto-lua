#!/bin/bash

make LUADIR=/lua_install

luacheck --std max+busted *.lua spec
busted --verbose --coverage
luacov spec, paseto.lua
