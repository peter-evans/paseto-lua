local v2protocol = {
  _VERSION     = 'paseto v0.1.0',
  _DESCRIPTION = 'PASETO (Platform-Agnostic Security Tokens) for Lua',
  _URL         = 'https://github.com/peter-evans/paseto-lua',
  _LICENSE     = [[
    MIT License

    Copyright (c) 2018 Peter Evans

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
  ]]
}

local HEADER = "v2"
local SYMMETRIC_KEY_BYTES = 32
local CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES = 24

function v2protocol.get_symmetric_key_byte_length()
  return SYMMETRIC_KEY_BYTES
end

function v2protocol.generate_symmetric_key()
  return require("luatweetnacl").randombytes(SYMMETRIC_KEY_BYTES)
end

function v2protocol.generate_asymmetric_secret_key()
  local _, secret_key = require("luatweetnacl").sign_keypair()
  return secret_key
end

function v2protocol.encrypt(key, payload)
  local luanacha = require("luanacha")
  -- build nonce
  local nonce_key = luanacha.randombytes(CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES)
  local blake2b_ctx = luanacha.blake2b_init(CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES, nonce_key)
  luanacha.blake2b_update(blake2b_ctx, payload)
  local nonce = luanacha.blake2b_final(blake2b_ctx)

  -- TODO: build ad

  local cipher = luanacha.lock(key, nonce, payload)

  return nonce, cipher
end

return v2protocol
