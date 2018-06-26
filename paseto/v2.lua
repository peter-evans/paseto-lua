local v2 = {
  _VERSION     = 'paseto v0.2.0',
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
local luasodium = require("luasodium")
local basexx = require("basexx")
local struct = require("struct")

function v2.__pre_auth_encode(...)
  local encoded = struct.pack("<L", #{...})
  for _, piece in ipairs({...})
  do
    encoded = encoded .. struct.pack("<L", #piece) .. piece
  end
  return encoded
end

function v2.__validate_and_remove_footer(token, footer)
  if not footer or footer == "" then
    return token
  end
  footer = basexx.to_url64(footer)
  local trailing = string.sub(token, #token - #footer + 1, #token)
  if trailing ~= footer then
    return nil, "Invalid message footer"
  end
  return string.sub(token, 1, #token - #footer - 1)
end

local function aead_encrypt(key, payload, header, footer, nonce_key)
  if #nonce_key == 0 then
    nonce_key = luasodium.randombytes(luasodium.SYMMETRIC_NONCEBYTES)
  end
  local nonce = luasodium.generichash(payload, nonce_key, luasodium.SYMMETRIC_NONCEBYTES)
  local additional_data = v2.__pre_auth_encode(header, nonce, footer)
  local ciphertext, err = luasodium.aead_encrypt(payload, additional_data, nonce, key)
  if not ciphertext then
    return nil, err
  end
  local token = header .. basexx.to_url64(nonce .. ciphertext) ..
    (#footer > 0 and "." .. basexx.to_url64(footer) or "")

  return token
end

local function aead_decrypt(key, encrypted, header, footer)
  if header ~= string.sub(encrypted, 1, #header) then
    return nil, "Invalid message header"
  end
  local decoded = basexx.from_url64(string.sub(encrypted, #header + 1))
  local nonce = string.sub(decoded, 1, luasodium.SYMMETRIC_NONCEBYTES)
  local ciphertext = string.sub(decoded, luasodium.SYMMETRIC_NONCEBYTES + 1, #decoded)
  local additional_data = v2.__pre_auth_encode(header, nonce, footer)
  local decrypted, err = luasodium.aead_decrypt(ciphertext, additional_data, nonce, key)
  return decrypted, err
end

function v2.__encrypt(key, payload, footer, nonce)
  nonce = nonce or ""
  return aead_encrypt(key, payload, PROTOCOL_VERSION .. ".local.", footer, nonce)
end

local function split_token(token)
  local t = {}
  local i = 1
  for str in string.gmatch(token, "[^.]+") do
    t[i] = str
    i = i + 1
  end
  return t
end

-- API --

function v2.get_symmetric_key_byte_length()
  return luasodium.SYMMETRIC_KEYBYTES
end

function v2.get_asymmetric_public_key_byte_length()
  return luasodium.SIGN_PUBLICKEYBYTES
end

function v2.get_asymmetric_secret_key_byte_length()
  return luasodium.SIGN_SECRETKEYBYTES
end

function v2.generate_symmetric_key()
  return luasodium.randombytes(luasodium.SYMMETRIC_KEYBYTES)
end

function v2.generate_asymmetric_secret_key()
  return luasodium.sign_keypair()
end

function v2.extract_version_purpose(token)
  if type(token) ~= "string" then
    return nil, nil, "Invalid token format"
  end
  local token_parts = split_token(token)
  if #token_parts >= 3 then
    return token_parts[1], token_parts[2]
  else
    return nil, nil, "Invalid token format"
  end
end

function v2.encrypt(key, payload, footer)
  footer = footer or ""
  return v2.__encrypt(key, payload, footer)
end

function v2.decrypt(key, token, footer)
  footer = footer or ""
  local encrypted_payload, err = v2.__validate_and_remove_footer(token, footer)
  if not encrypted_payload then
    return nil, err
  end
  return aead_decrypt(key, encrypted_payload, PROTOCOL_VERSION .. ".local.", footer)
end

function v2.sign(secret_key, message, footer)
  footer = footer or ""
  local header = PROTOCOL_VERSION .. ".public."
  local data = v2.__pre_auth_encode(header, message, footer)
  local signature = luasodium.sign_detached(data, secret_key)
  local token = header .. basexx.to_url64(message .. signature) ..
    (#footer > 0 and "." .. basexx.to_url64(footer) or "")
  return token
end

function v2.verify(public_key, token, footer)
  footer = footer or ""
  local signed_payload, err = v2.__validate_and_remove_footer(token, footer)
  if not signed_payload then
    return nil, err
  end
  local header = PROTOCOL_VERSION .. ".public."
  if header ~= string.sub(signed_payload, 1, #header) then
    return nil, "Invalid message header"
  end
  local decoded = basexx.from_url64(string.sub(signed_payload, #header + 1))
  local message = string.sub(decoded, 1, #decoded - luasodium.SIGN_BYTES)
  local signature = string.sub(decoded, #decoded - luasodium.SIGN_BYTES + 1)
  local data = v2.__pre_auth_encode(header, message, footer)
  local verified
  verified, err = luasodium.sign_verify_detached(data, signature, public_key)
  if not verified then
    return nil, err
  end
  return message
end

return v2
