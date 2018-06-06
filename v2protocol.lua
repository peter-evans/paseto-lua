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

local PROTOCOL_VERSION = "v2"
local SYMMETRIC_KEY_BYTES = 32
local CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES = 24
local CRYPTO_SIGN_BYTES = 64

function v2protocol.get_symmetric_key_byte_length()
  return SYMMETRIC_KEY_BYTES
end

function v2protocol.generate_symmetric_key()
  return require("luanacha").randombytes(SYMMETRIC_KEY_BYTES)
end

function v2protocol.generate_asymmetric_secret_key()
  local public_key, secret_key = require("luanacha").sign_keypair()
  return secret_key .. public_key
end

local function aead_encrypt(key, payload, header, footer, nonce_key)
  local luanacha = require("luanacha")
  local utils = require("utils")

  if #nonce_key == 0 then
    nonce_key = luanacha.randombytes(CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES)
  end

  local blake2b_ctx = luanacha.blake2b_init(CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES, nonce_key)
  luanacha.blake2b_update(blake2b_ctx, payload)
  nonce = luanacha.blake2b_final(blake2b_ctx)

  local additional_data = utils.pre_auth_encode(header, nonce, footer)
  local ciphertext = luanacha.aead_lock(key, nonce, payload, additional_data)
  local token = header .. utils.base64_encode(nonce .. ciphertext, true) ..
    (#footer > 0 and "." .. utils.base64_encode(footer, true) or "")

  return token
end

local function aead_decrypt(key, encrypted, header, footer)
  local luanacha = require("luanacha")
  local utils = require("utils")

  if header ~= string.sub(encrypted, 1, #header) then
    error("Invalid message header")
  end

  local decoded = utils.base64_decode(string.sub(encrypted, #header + 1))
  local nonce = string.sub(decoded, 1, CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES)
  local ciphertext = string.sub(decoded, CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES + 1, #decoded)
  local additional_data = utils.pre_auth_encode(header, nonce, footer)
  local decrypted = luanacha.aead_unlock(key, nonce, ciphertext, additional_data)

  return decrypted
end

function v2protocol.__encrypt(key, payload, footer, nonce)
  nonce = nonce or ""
  return aead_encrypt(key, payload, PROTOCOL_VERSION .. ".local.", footer, nonce)
end

function v2protocol.encrypt(key, payload, footer)
  footer = footer or ""
  return v2protocol.__encrypt(key, payload, footer)
end

function v2protocol.decrypt(key, token, footer)
  local utils = require("utils")
  footer = footer or ""
  local encrypted_payload = utils.validate_and_remove_footer(token, footer)
  return aead_decrypt(key, encrypted_payload, PROTOCOL_VERSION .. ".local.", footer)
end

function v2protocol.sign(secret_key, public_key, message, footer)
  local luanacha = require("luanacha")
  local utils = require("utils")
  footer = footer or ""

  local header = PROTOCOL_VERSION .. ".public."
  local data = utils.pre_auth_encode(header .. message .. footer)
  local signature = luanacha.sign(secret_key, public_key, data)
  local token = header .. utils.base64_encode(message .. signature, true) ..
    (#footer > 0 and "." .. utils.base64_encode(footer, true) or "")

  return token
end

function v2protocol.verify(public_key, token, footer)
  local luanacha = require("luanacha")
  local utils = require("utils")
  footer = footer or ""

  local signed_payload = utils.validate_and_remove_footer(token, footer)
  local header = PROTOCOL_VERSION .. ".public."

  if header ~= string.sub(signed_payload, 1, #header) then
    error("Invalid message header")
  end

  local decoded = utils.base64_decode(string.sub(signed_payload, #header + 1))
  local message = string.sub(decoded, 1, #decoded - CRYPTO_SIGN_BYTES)
  local signature = string.sub(decoded, #decoded - CRYPTO_SIGN_BYTES + 1)
  local data = utils.pre_auth_encode(header .. message .. footer)

  if not luanacha.check(signature, public_key, data) then
    error("Invalid signature for this message")
  end

  return message
end

return v2protocol
