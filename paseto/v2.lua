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

local paseto = require "paseto.v2.core"
local json = require "cjson"

local function decode_json(data)
  local ok, decoded = pcall(function()
    return json.decode(data)
  end)
  if not ok then
    return nil, "Invalid JSON"
  end
  return decoded
end

-- API --

v2.SYMMETRIC_KEY_BYTES = paseto.SYMMETRIC_KEY_BYTES
v2.ASYMMETRIC_PUBLIC_KEY_BYTES = paseto.ASYMMETRIC_PUBLIC_KEY_BYTES
v2.ASYMMETRIC_SECRET_KEY_BYTES = paseto.ASYMMETRIC_SECRET_KEY_BYTES

function v2.generate_symmetric_key()
  return paseto.generate_symmetric_key()
end

function v2.generate_asymmetric_secret_key()
  return paseto.generate_asymmetric_secret_key()
end

function v2.extract_version_purpose(token)
  return paseto.extract_version_purpose(token)
end

function v2.extract_footer_claims(token)
  local footer, err = paseto.extract_footer(token)
  if footer == nil then
    return nil, err
  end
  if footer == "" then
    return {}
  end
  local footer_claims
  footer_claims, err = decode_json(footer)
  if footer_claims == nil then
    return nil, err
  end
  return footer_claims
end

function v2.encrypt(key, payload, footer)
  return paseto.encrypt(key, payload, footer)
end

function v2.decrypt(key, token, footer)
  return paseto.decrypt(key, token, footer)
end

function v2.sign(secret_key, message, footer)
  return paseto.sign(secret_key, message, footer)
end

function v2.verify(public_key, token, footer)
  return paseto.verify(public_key, token, footer)
end

return v2
