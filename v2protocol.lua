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

local function aead_encrypt(key, payload, header, footer, nonce)
  local luanacha = require("luanacha")
  local utils = require("utils")

  if not nonce then
    local nonce_key = luanacha.randombytes(CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES)
    local blake2b_ctx = luanacha.blake2b_init(CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES, nonce_key)
    luanacha.blake2b_update(blake2b_ctx, payload)
    nonce = luanacha.blake2b_final(blake2b_ctx)
  end

  local additional_data = utils.pre_auth_encode(header .. nonce .. footer)
  local ciphertext = luanacha.aead_lock(key, nonce, payload, additional_data)
  local token = header .. utils.base64_encode(nonce .. ciphertext, true) .. (#footer > 0 and "." .. utils.base64_encode(footer, true) or "")

  return token
end

local function aead_decrypt(key, encrypted, header, footer)
  local luanacha = require("luanacha")
  local utils = require("utils")

  if header ~= string.sub(encrypted, 0, #header) then
    error("Invalid message header.")
  end

  -- Use pcall here?
  local decoded = utils.base64_decode(string.sub(encrypted, #header + 1))
  local nonce = string.sub(decoded, 1, CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES)
  local ciphertext = string.sub(decoded, CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES + 1, #decoded)
  local additional_data = utils.pre_auth_encode(header .. nonce .. footer)
  local decrypted = luanacha.aead_unlock(key, nonce, ciphertext, additional_data)

  return decrypted
end

function v2protocol.encrypt(key, payload, footer)
  footer = footer or ""
  return aead_encrypt(key, payload, HEADER .. ".local.", footer)
end

function v2protocol.decrypt(key, encrypted, footer)
  footer = footer or ""
  return aead_decrypt(key, encrypted, HEADER .. ".local.", footer)
end

return v2protocol
