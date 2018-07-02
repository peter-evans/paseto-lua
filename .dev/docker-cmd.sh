#!/bin/bash

luarocks make

luacheck --std max+busted --no-max-line-length paseto spec
busted --verbose --coverage
luacov paseto, spec
