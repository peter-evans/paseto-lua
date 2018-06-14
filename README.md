# [PASETO](https://github.com/paragonie/paseto) (Platform-Agnostic Security Tokens) for Lua
[![luarocks](https://img.shields.io/badge/luarocks-paseto-blue.svg)](https://luarocks.org/modules/peterevans/paseto)
[![Build Status](https://travis-ci.org/peter-evans/paseto-lua.svg?branch=master)](https://travis-ci.org/peter-evans/paseto-lua)
[![Coverage Status](https://coveralls.io/repos/github/peter-evans/paseto-lua/badge.svg?branch=master)](https://coveralls.io/github/peter-evans/paseto-lua?branch=master)

Paseto (Platform-Agnostic SEcurity TOkens) is a specification and reference implementation for secure stateless tokens.

>__*"Paseto is everything you love about JOSE (JWT, JWE, JWS) without any of the [many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid)."*__

— [https://github.com/paragonie/paseto](https://github.com/paragonie/paseto)

## Feature Support

| v1.local | v1.public | v2.local | v2.public |
| :---: | :---: | :---: | :---: |
| :x: | :x: | :heavy_check_mark: | :heavy_check_mark: |

- v2 local authentication (Blake2b and XChaCha20-Poly1305)
- v2 public authentication (Ed25519 signatures)

This implementation doesn't currently support the v1 protocol. However, please note that v1 is recommended only for legacy systems that cannot use modern cryptography.

## Installation

This Lua module depends on the [Sodium crypto library (libsodium)](https://github.com/jedisct1/libsodium).
The following is a convenient way to install libsodium via LuaRocks.
I don't necessarily recommend this for production use. Please see [libsodium's documentation](https://download.libsodium.org/doc/installation/) for full installation instructions.
```
luarocks install libsodium
```

Then install PASETO:
```
luarocks install paseto
```

## Usage

__v2.local__ :
```
local paseto = require "paseto.v2"

local key, message, token, footer, decrypted
message = "my secret message"
footer = "my footer"

-- generate symmetric key
key = paseto.generate_symmetric_key()

-- encrypt/decrypt without footer
token = paseto.encrypt(key, message)
decrypted = paseto.decrypt(key, token)

-- encrypt/decrypt with footer
token = paseto.encrypt(key, message, footer)
decrypted = paseto.decrypt(key, token, footer)
```

__v2.public__ :
```
local paseto = require "paseto.v2"

local secret_key, public_key, message, token, footer, verified
message = "my secret message"
footer = "my footer"

-- generate key pair
secret_key, public_key = paseto.generate_asymmetric_secret_key()

-- sign/verify without footer
token = paseto.sign(secret_key, message)
verified = paseto.verify(public_key, token)

-- sign/verify with footer
token = paseto.sign(secret_key, message, footer)
verified = paseto.verify(public_key, token, footer)
```

## License

MIT License - see the [LICENSE](LICENSE) file for details
