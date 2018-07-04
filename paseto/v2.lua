local v2 = {
  _VERSION     = 'paseto v0.3.0',
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
local date = require "date"

local function encode_json(data)
  local ok, encoded = pcall(function()
    return json.encode(data)
  end)
  if not ok then
    return nil, "Invalid data"
  end
  return encoded
end

local function decode_json(data)
  local ok, decoded = pcall(function()
    return json.decode(data)
  end)
  if not ok then
    return nil, "Invalid JSON"
  end
  return decoded
end

local function required_claim_exists(payload_claims, key)
  if payload_claims[key] == nil then
    return false, "Missing required claim '" .. key .."'"
  end
  return true
end

local function claim_matches_expected_value(payload_claims, key, value)
  local exists, err = required_claim_exists(payload_claims, key)
  if exists == false then
    return false, err
  end
  if payload_claims[key] ~= value then
    return false, "Claim '" .. key .."' does not match the expected value"
  end
  return true
end

local function claim_exp_is_valid(payload_claims)
  local key = "exp"
  local exists, err = required_claim_exists(payload_claims, key)
  if exists == false then
    return false, err
  end
  if date(payload_claims[key]) < date(os.time()) then
    return false, "Token has expired"
  end
  return true
end

local function claim_iat_is_valid(payload_claims)
  local key = "iat"
  local exists, err = required_claim_exists(payload_claims, key)
  if exists == false then
    return false, err
  end
  if date(payload_claims[key]) > date(os.time()) then
    return false, "Token was issued in the future"
  end
  return true
end

local function claim_nbf_is_valid(payload_claims)
  local key = "nbf"
  local exists, err = required_claim_exists(payload_claims, key)
  if exists == false then
    return false, err
  end
  if date(payload_claims[key]) > date(os.time()) then
    return false, "Token cannot be used yet"
  end
  return true
end

local registered_claims = {
  ForAudience = function(payload_claims, value)
    return claim_matches_expected_value(payload_claims, "aud", value)
  end,
  IdentifiedBy = function(payload_claims, value)
    return claim_matches_expected_value(payload_claims, "jti", value)
  end,
  IssuedBy = function(payload_claims, value)
    return claim_matches_expected_value(payload_claims, "iss", value)
  end,
  Subject = function(payload_claims, value)
    return claim_matches_expected_value(payload_claims, "sub", value)
  end,
  NotExpired = function(payload_claims)
    return claim_exp_is_valid(payload_claims)
  end,
  ValidAt = function(payload_claims)
    local valid, err
    valid, err = claim_iat_is_valid(payload_claims)
    if valid == false then
      return false, err
    end
    valid, err = claim_nbf_is_valid(payload_claims)
    if valid == false then
      return false, err
    end
    valid, err = claim_exp_is_valid(payload_claims)
    if valid == false then
      return false, err
    end
  end,
  ContainsClaim = function(payload_claims, value)
    local exists, err = required_claim_exists(payload_claims, value)
    if exists == false then
      return false, err
    end
    return true
  end
}

local function validate_claims(payload_claims, claim_rules)
  if type(claim_rules) ~= "table" then
    return false, "Invalid claim rules format"
  end
  for key, value in pairs(claim_rules) do
    if registered_claims[key] ~= nil then
      local valid, err = registered_claims[key](payload_claims, value)
      if valid == false then
        return false, err
      end
    else
      local matches, err = claim_matches_expected_value(payload_claims, key, value)
      if matches == false then
        return false, err
      end
    end
  end
  return true
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
    return nil, nil, err
  end
  if footer == "" then
    return {}, footer
  end
  local footer_claims
  footer_claims, err = decode_json(footer)
  if footer_claims == nil then
    return nil, nil, err
  end
  return footer_claims, footer
end

function v2.encrypt(key, payload_claims, footer_claims)
  local payload, footer
  payload = encode_json(payload_claims)
  if payload == nil or type(payload_claims) ~= "table" then
    return nil, "Invalid payload claims"
  end
  if footer_claims == nil then
    footer = ""
  else
    footer = encode_json(footer_claims)
    if footer == nil or type(footer_claims) ~= "table" then
      return nil, "Invalid footer claims"
    end
  end
  return paseto.encrypt(key, payload, footer)
end

function v2.decrypt(key, token, claim_rules, footer)
  local err, decrypted, payload_claims, valid
  decrypted, err = paseto.decrypt(key, token, footer)
  if decrypted == nil then
    return nil, err
  end
  payload_claims, err = decode_json(decrypted)
  if payload_claims == nil then
    return nil, err
  end
  if claim_rules ~= nil then
    valid, err = validate_claims(payload_claims, claim_rules)
    if valid == false then
      return nil, err
    end
  end
  return payload_claims
end

function v2.sign(secret_key, payload_claims, footer_claims)
  local payload, footer
  payload = encode_json(payload_claims)
  if payload == nil or type(payload_claims) ~= "table" then
    return nil, "Invalid payload claims"
  end
  if footer_claims == nil then
    footer = ""
  else
    footer = encode_json(footer_claims)
    if footer == nil or type(footer_claims) ~= "table" then
      return nil, "Invalid footer claims"
    end
  end
  return paseto.sign(secret_key, payload, footer)
end

function v2.verify(public_key, token, claim_rules, footer)
  local err, verified_claims, payload_claims, valid
  verified_claims, err = paseto.verify(public_key, token, footer)
  if verified_claims == nil then
    return nil, err
  end
  payload_claims, err = decode_json(verified_claims)
  if payload_claims == nil then
    return nil, err
  end
  if claim_rules ~= nil then
    valid, err = validate_claims(payload_claims, claim_rules)
    if valid == false then
      return nil, err
    end
  end
  return payload_claims
end

return v2
