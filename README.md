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

This implementation doesn't support the v1 protocol. Please note that v1 should only be used by legacy systems that cannot use modern cryptography.

#### Roadmap
- [x] v2 local authentication (Blake2b and XChaCha20-Poly1305)
- [x] v2 public authentication (Ed25519 signatures)
- [x] JSON payload and footer processing
- [ ] Claims validation
- [ ] Integrated key ID (kid) support
- [ ] High-level token builder API
- [ ] API documentation

## Installation

#### Sodium Crypto Library

This Lua module depends on the [Sodium crypto library (libsodium)](https://github.com/jedisct1/libsodium).
The following is a convenient way to install libsodium via LuaRocks.
I don't necessarily recommend this for production use. Please see [libsodium's documentation](https://download.libsodium.org/doc/installation/) for full installation instructions.
```
luarocks install libsodium
```

#### Lua CJSON

This module also has a dependency on [lua-cjson](https://luarocks.org/modules/openresty/lua-cjson).
Due to an issue with the latest version you might need to specify an earlier stable version.
If you let luarocks install this dependency for you when installing PASETO you might experience problems.
Additionally, if using Lua 5.3 you need to build Lua with a compatibility flag for Lua 5.1.

| Lua Environment | Lua CJSON install | Lua compatibility flags |
| :---: | :---: | :---: |
| 5.1 | `luarocks install lua-cjson 2.1.0` | |
| 5.2 | `luarocks install lua-cjson 2.1.0` | |
| 5.3 | `luarocks install lua-cjson 2.1.0` | -DLUA_COMPAT_5_1 |
| Lua JIT 2.0 | `luarocks install lua-cjson 2.1.0` | |
| Lua JIT 2.1 | `luarocks install lua-cjson 2.1.0.6` | |

See this repository's [Travis CI configuration](.travis.yml) for build configurations.

#### PASETO
Finally install PASETO:
```
luarocks install paseto
```

## Usage

__v2.local__ :
```
local paseto = require "paseto.v2"

local key, payload_claims, token, footer_claims
local extracted_footer_claims, extracted_footer, decrypted_claims
payload_claims = {}
payload_claims["clientid"] = 100099
payload_claims["message"] = "secret"
footer_claims = { kid = "123456789" }

-- generate symmetric key
key = paseto.generate_symmetric_key()

-- encrypt/decrypt without footer
token = paseto.encrypt(key, payload_claims)
decrypted_claims = paseto.decrypt(key, token)

-- encrypt/decrypt with footer
token = paseto.encrypt(key, payload_claims, footer_claims)
extracted_footer_claims, extracted_footer = paseto.extract_footer_claims(token)
decrypted_claims = paseto.decrypt(key, token, extracted_footer)
```

__v2.public__ :
```
local paseto = require "paseto.v2"

local secret_key, public_key, payload_claims, token, footer_claims
local extracted_footer_claims, extracted_footer, verified_claims
payload_claims = {}
payload_claims["clientid"] = 100099
payload_claims["message"] = "secret"
footer_claims = { kid = "123456789" }

-- generate key pair
secret_key, public_key = paseto.generate_asymmetric_secret_key()

-- sign/verify without footer
token = paseto.sign(secret_key, payload_claims)
verified_claims = paseto.verify(public_key, token)

-- sign/verify with footer
token = paseto.sign(secret_key, payload_claims, footer_claims)
extracted_footer_claims, extracted_footer = paseto.extract_footer_claims(token)
verified_claims = paseto.verify(public_key, token, extracted_footer)
```

#### Core API
This low-level API should only be used when you cannot use JSON for payload claims and footer claims.

__v2.local__ :
```
local paseto = require "paseto.v2.core"

local key, message, token, footer, extracted_footer, decrypted
message = "my secret message"
footer = "my footer"

-- generate symmetric key
key = paseto.generate_symmetric_key()

-- encrypt/decrypt without footer
token = paseto.encrypt(key, message)
decrypted = paseto.decrypt(key, token)

-- encrypt/decrypt with footer
token = paseto.encrypt(key, message, footer)
extracted_footer = paseto.extract_footer(token)
decrypted = paseto.decrypt(key, token, extracted_footer)
```

__v2.public__ :
```
local paseto = require "paseto.v2.core"

local secret_key, public_key, message, token, footer, extracted_footer, verified
message = "my secret message"
footer = "my footer"

-- generate key pair
secret_key, public_key = paseto.generate_asymmetric_secret_key()

-- sign/verify without footer
token = paseto.sign(secret_key, message)
verified = paseto.verify(public_key, token)

-- sign/verify with footer
token = paseto.sign(secret_key, message, footer)
extracted_footer = paseto.extract_footer(token)
verified = paseto.verify(public_key, token, extracted_footer)
```

## License

MIT License - see the [LICENSE](LICENSE) file for details
