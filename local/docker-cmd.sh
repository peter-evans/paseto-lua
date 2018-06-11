#!/bin/bash

luarocks make

luacheck --std max+busted paseto spec
busted --verbose --coverage
luacov paseto, spec
