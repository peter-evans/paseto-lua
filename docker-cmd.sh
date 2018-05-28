#!/bin/bash

luacheck --std max+busted *.lua spec
busted --verbose --coverage
luacov spec, paseto.lua
