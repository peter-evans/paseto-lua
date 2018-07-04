local paseto = require "paseto.v2"
local basexx = require "basexx"
local date = require "date"

describe("v2 protocol standard API", function()

  describe("extract footer claims", function()

    local key, secret_key, payload_claims, footer_claims

    setup(function()
      key = paseto.generate_symmetric_key()
      secret_key = paseto.generate_asymmetric_secret_key()
      payload_claims = { message = "test" }
      footer_claims = { kid = "123456789" }
    end)

    it("should extract the footer claims from a 'local' token", function()
      local token = paseto.encrypt(key, payload_claims, footer_claims)
      local extracted_footer_claims = paseto.extract_footer_claims(token)
      assert.equal("table", type(extracted_footer_claims))
      assert.equal(footer_claims.kid, extracted_footer_claims.kid)
    end)

    it("should extract the footer claims from a 'public' token", function()
      local token = paseto.sign(secret_key, payload_claims, footer_claims)
      local extracted_footer_claims = paseto.extract_footer_claims(token)
      assert.equal("table", type(extracted_footer_claims))
      assert.equal(footer_claims.kid, extracted_footer_claims.kid)
    end)

    it("should return an empty table for tokens without a footer", function()
      local token = paseto.sign(secret_key, payload_claims)
      local extracted_footer_claims = paseto.extract_footer_claims(token)
      assert.equal("table", type(extracted_footer_claims))
      assert.equal(#{}, #extracted_footer_claims)
    end)

    it("should raise error 'Invalid token format' for malformed tokens", function()
      local extracted_footer_claims, _, err = paseto.extract_footer_claims("v2.public")
      assert.equal(nil, extracted_footer_claims)
      assert.equal("Invalid token format", err)
    end)

    it("should raise error 'Invalid JSON'", function()
      local malformed_footer = basexx.to_url64("test")
      local extracted_footer_claims, _, err = paseto.extract_footer_claims("v2.public.abc." .. malformed_footer)
      assert.equal(nil, extracted_footer_claims)
      assert.equal("Invalid JSON", err)
    end)

    it("should raise error 'Invalid token format' for nil values", function()
      local extracted_footer_claims, _, err = paseto.extract_footer_claims()
      assert.equal(nil, extracted_footer_claims)
      assert.equal("Invalid token format", err)
    end)

  end)

  describe("authenticated encryption", function()

    local key, payload_claims, footer_claims

    setup(function()
      local now = date(os.time())
      key = paseto.generate_symmetric_key()
      payload_claims = {}
      payload_claims["iss"] = "paragonie.com"
      payload_claims["jti"] = "87IFSGFgPNtQNNuw0AtuLttP"
      payload_claims["aud"] = "some-audience.com"
      payload_claims["sub"] = "test"
      payload_claims["iat"] = now:fmt("${iso}%z")
      payload_claims["nbf"] = now:fmt("${iso}%z")
      payload_claims["exp"] = now:addminutes(10):fmt("${iso}%z")
      payload_claims["data"] = "this is a secret message"
      payload_claims["myclaim"] = "validate this"
      footer_claims = { kid = "123456789" }
    end)

    it("should encrypt and decrypt payload claims without footer", function()
      local token = paseto.encrypt(key, payload_claims)
      assert.equal("string", type(token))
      assert.equal("v2.local.", string.sub(token, 1, 9))

      local decrypted_claims = paseto.decrypt(key, token)
      assert.equal("table", type(decrypted_claims))
      assert.equal(#payload_claims, #decrypted_claims)
      assert.equal(payload_claims.data, decrypted_claims.data)
    end)

    it("should encrypt and decrypt payload claims with footer", function()
      local token = paseto.encrypt(key, payload_claims, footer_claims)
      assert.equal("string", type(token))
      assert.equal("v2.local.", string.sub(token, 1, 9))

      local _, extracted_footer = paseto.extract_footer_claims(token)
      local decrypted_claims = paseto.decrypt(key, token, nil, extracted_footer)
      assert.equal("table", type(decrypted_claims))
      assert.equal(#payload_claims, #decrypted_claims)
      assert.equal(payload_claims.data, decrypted_claims.data)
    end)

    it("should raise error 'Invalid payload claims'", function()
      local token, err = paseto.encrypt(key, "invalid")
      assert.equal(nil, token)
      assert.equal("Invalid payload claims", err)
    end)

    it("should raise error 'Invalid footer claims'", function()
      local token, err = paseto.encrypt(key, payload_claims, "invalid")
      assert.equal(nil, token)
      assert.equal("Invalid footer claims", err)
    end)

    it("should raise error 'Invalid key size'", function()
      local token, err = paseto.encrypt("\0", payload_claims)
      assert.equal(nil, token)
      assert.equal("Invalid key size", err)
    end)

    it("should raise error 'Invalid message header'", function()
      local decrypted_claims, err = paseto.decrypt(key, "invalid")
      assert.equal(nil, decrypted_claims)
      assert.equal("Invalid message header", err)
    end)

    it("should raise error 'Message forged'", function()
      local decrypted_claims, err = paseto.decrypt(key, "v2.local.forged")
      assert.equal(nil, decrypted_claims)
      assert.equal("Message forged", err)
    end)

    it("should raise error 'Message forged' when key is invalid", function()
      local token = paseto.encrypt(key, payload_claims)
      local decrypted_claims, err = paseto.decrypt("\0", token)
      assert.equal(nil, decrypted_claims)
      assert.equal("Message forged", err)
    end)

    it("should raise error 'Invalid message footer'", function()
      local token = paseto.encrypt(key, payload_claims)
      local decrypted_claims, err = paseto.decrypt(key, token, nil, "footer")
      assert.equal(nil, decrypted_claims)
      assert.equal("Invalid message footer", err)
    end)

    it("should raise error 'Invalid JSON' for non-JSON payloads", function()
      local key_2 = basexx.from_url64("euU5aFRziIG1VE8m6_ImHPt2h7dlO8Pww49B_dIV2lQ")
      local token = "v2.local.2v2RENdT5E_z-kA-u0h0bQZeQ2DTpfT5yHCJcgRunCUafeiHjDovw35tDqA"
      local decrypted_claims, err = paseto.decrypt(key_2, token)
      assert.equal(nil, decrypted_claims)
      assert.equal("Invalid JSON", err)
    end)

    describe("claims validation", function()

      it("should encrypt and decrypt payload claims successfully with claims validation", function()
        local token = paseto.encrypt(key, payload_claims)
        local claim_rules = { data = "this is a secret message", myclaim = "validate this" }
        local decrypted_claims = paseto.decrypt(key, token, claim_rules)
        assert.equal("table", type(decrypted_claims))
        assert.equal(#payload_claims, #decrypted_claims)
        assert.equal(payload_claims.data, decrypted_claims.data)
      end)

      it("should encrypt and decrypt payload claims successfully with registered claims validation", function()
        payload_claims["exp"] = date(os.time()):addminutes(10):fmt("${iso}%z")
        local token = paseto.encrypt(key, payload_claims)
        local claim_rules = {
          ForAudience = "some-audience.com",
          IdentifiedBy = "87IFSGFgPNtQNNuw0AtuLttP",
          IssuedBy = "paragonie.com",
          Subject = "test",
          NotExpired = true,
          ValidAt = true,
          ContainsClaim = "data"
        }
        local decrypted_claims = paseto.decrypt(key, token, claim_rules)
        assert.equal("table", type(decrypted_claims))
        assert.equal(#payload_claims, #decrypted_claims)
        assert.equal(payload_claims.data, decrypted_claims.data)
      end)

      it("should raise error 'Invalid claim rules format'", function()
        local token = paseto.encrypt(key, payload_claims)
        local claim_rules = "invalid format"
        local decrypted_claims, err = paseto.decrypt(key, token, claim_rules)
        assert.equal(nil, decrypted_claims)
        assert.equal("Invalid claim rules format", err)
      end)

      it("should raise error 'Missing required claim 'required_claim''", function()
        local token = paseto.encrypt(key, payload_claims)
        local claim_rules = { required_claim = "this is a secret message", myclaim = "validate this" }
        local decrypted_claims, err = paseto.decrypt(key, token, claim_rules)
        assert.equal(nil, decrypted_claims)
        assert.equal("Missing required claim 'required_claim'", err)
      end)

      it("should raise error 'Claim 'myclaim' does not match the expected value'", function()
        local token = paseto.encrypt(key, payload_claims)
        local claim_rules = { data = "this is a secret message", myclaim = "invalid" }
        local decrypted_claims, err = paseto.decrypt(key, token, claim_rules)
        assert.equal(nil, decrypted_claims)
        assert.equal("Claim 'myclaim' does not match the expected value", err)
      end)

      it("should raise error 'Claim 'aud' does not match the expected value' when validating rule 'ForAudience'", function()
        local token = paseto.encrypt(key, payload_claims)
        local claim_rules = { ForAudience = "some-other-audience.com" }
        local decrypted_claims, err = paseto.decrypt(key, token, claim_rules)
        assert.equal(nil, decrypted_claims)
        assert.equal("Claim 'aud' does not match the expected value", err)
      end)

      it("should raise error 'Missing required claim 'exp''", function()
        local token = paseto.encrypt(key, {})
        local claim_rules = { NotExpired = true }
        local decrypted_claims, err = paseto.decrypt(key, token, claim_rules)
        assert.equal(nil, decrypted_claims)
        assert.equal("Missing required claim 'exp'", err)
      end)

      it("should raise error 'Token has expired'", function()
        payload_claims["exp"] = date(os.time()):addseconds(-1):fmt("${iso}%z")
        local token = paseto.encrypt(key, payload_claims)
        local claim_rules = { NotExpired = true }
        local decrypted_claims, err = paseto.decrypt(key, token, claim_rules)
        assert.equal(nil, decrypted_claims)
        assert.equal("Token has expired", err)
      end)

      it("should raise error 'Token was issued in the future'", function()
        local future = date(os.time()):addminutes(10)
        payload_claims["iat"] = future:fmt("${iso}%z")
        payload_claims["nbf"] = future:fmt("${iso}%z")
        payload_claims["exp"] = future:fmt("${iso}%z")
        local token = paseto.encrypt(key, payload_claims)
        local claim_rules = { ValidAt = true }
        local decrypted_claims, err = paseto.decrypt(key, token, claim_rules)
        assert.equal(nil, decrypted_claims)
        assert.equal("Token was issued in the future", err)
      end)

      it("should raise error 'Token cannot be used yet'", function()
        local now = date(os.time())
        local future = date(os.time()):addminutes(10)
        payload_claims["iat"] = now:fmt("${iso}%z")
        payload_claims["nbf"] = future:fmt("${iso}%z")
        payload_claims["exp"] = future:fmt("${iso}%z")
        local token = paseto.encrypt(key, payload_claims)
        local claim_rules = { ValidAt = true }
        local decrypted_claims, err = paseto.decrypt(key, token, claim_rules)
        assert.equal(nil, decrypted_claims)
        assert.equal("Token cannot be used yet", err)
      end)

      it("should raise error 'Token has expired'", function()
        local now = date(os.time())
        local past = date(os.time()):addminutes(-10)
        payload_claims["iat"] = now:fmt("${iso}%z")
        payload_claims["nbf"] = now:fmt("${iso}%z")
        payload_claims["exp"] = past:fmt("${iso}%z")
        local token = paseto.encrypt(key, payload_claims)
        local claim_rules = { ValidAt = true }
        local decrypted_claims, err = paseto.decrypt(key, token, claim_rules)
        assert.equal(nil, decrypted_claims)
        assert.equal("Token has expired", err)
      end)

      it("should raise error 'Missing required claim 'important_claim'", function()
        local token = paseto.encrypt(key, payload_claims)
        local claim_rules = { ContainsClaim = "important_claim" }
        local decrypted_claims, err = paseto.decrypt(key, token, claim_rules)
        assert.equal(nil, decrypted_claims)
        assert.equal("Missing required claim 'important_claim'", err)
      end)

    end)

  end)

  describe("signing", function()

    local secret_key, public_key, payload_claims, footer_claims

    setup(function()
      local now = date(os.time())
      secret_key, public_key = paseto.generate_asymmetric_secret_key()
      payload_claims = {}
      payload_claims["iss"] = "paragonie.com"
      payload_claims["jti"] = "87IFSGFgPNtQNNuw0AtuLttP"
      payload_claims["aud"] = "some-audience.com"
      payload_claims["sub"] = "test"
      payload_claims["iat"] = now:fmt("${iso}%z")
      payload_claims["nbf"] = now:fmt("${iso}%z")
      payload_claims["exp"] = now:addminutes(10):fmt("${iso}%z")
      payload_claims["data"] = "this is a signed message"
      payload_claims["myclaim"] = "validate this"
      footer_claims = { kid = "123456789" }
    end)

    it("should sign and verify payload claims successfully without footer", function()
      local token = paseto.sign(secret_key, payload_claims)
      assert.equal("string", type(token))
      assert.equal("v2.public.", string.sub(token, 1, 10))

      local verified_claims = paseto.verify(public_key, token)
      assert.equal("table", type(verified_claims))
      assert.equal(#payload_claims, #verified_claims)
      assert.equal(payload_claims.data, verified_claims.data)
    end)

    it("should sign and verify payload claims successfully with footer", function()
      local token = paseto.sign(secret_key, payload_claims, footer_claims)
      assert.equal("string", type(token))
      assert.equal("v2.public.", string.sub(token, 1, 10))

      local _, extracted_footer = paseto.extract_footer_claims(token)
      local verified_claims = paseto.verify(public_key, token, nil, extracted_footer)
      assert.equal("table", type(verified_claims))
      assert.equal(#payload_claims, #verified_claims)
      assert.equal(payload_claims.data, verified_claims.data)
    end)

    it("should raise error 'Invalid payload claims'", function()
      local token, err = paseto.sign(secret_key, "invalid")
      assert.equal(nil, token)
      assert.equal("Invalid payload claims", err)
    end)

    it("should raise error 'Invalid footer claims'", function()
      local token, err = paseto.sign(secret_key, payload_claims, "invalid")
      assert.equal(nil, token)
      assert.equal("Invalid footer claims", err)
    end)

    it("should raise error 'Invalid message header'", function()
      local verified_claims, err = paseto.verify(public_key, "invalid")
      assert.equal(nil, verified_claims)
      assert.equal("Invalid message header", err)
    end)

    it("should raise error 'Invalid signature for this message'", function()
      local verified_claims, err = paseto.verify(public_key, "v2.public.invalid")
      assert.equal(nil, verified_claims)
      assert.equal("Invalid signature for this message", err)
    end)

    it("should raise error 'Invalid message footer'", function()
      local token = paseto.sign(secret_key, payload_claims)
      local verified_claims, err = paseto.verify(public_key, token, nil, "footer")
      assert.equal(nil, verified_claims)
      assert.equal("Invalid message footer", err)
    end)

    it("should raise error 'Invalid JSON' for non-JSON payloads", function()
      local public_key_2 = basexx.from_url64("WaR_FA6w_ZPyqkYopQp4W622l5vZl-mXMwMhf6wUpTs")
      local token = "v2.public.dGVzdBpVe1EDoZfaooYBFGxcbhGTH3lc1Uqu0WNz5zbXoPIXOjJkKZ-fp_9brlGA77YQGdIpfZDDkbD_3GAQvvwtzgg"
      local verified_claims, err = paseto.verify(public_key_2, token)
      assert.equal(nil, verified_claims)
      assert.equal("Invalid JSON", err)
    end)

    describe("claims validation", function()

      it("should sign and verify payload claims successfully with claims validation", function()
        local token = paseto.sign(secret_key, payload_claims)
        local claim_rules = { data = "this is a signed message", myclaim = "validate this" }
        local verified_claims = paseto.verify(public_key, token, claim_rules)
        assert.equal("table", type(verified_claims))
        assert.equal(#payload_claims, #verified_claims)
        assert.equal(payload_claims.data, verified_claims.data)
      end)

      it("should encrypt and decrypt payload claims successfully with registered claims validation", function()
        payload_claims["exp"] = date(os.time()):addminutes(10):fmt("${iso}%z")
        local token = paseto.sign(secret_key, payload_claims)
        local claim_rules = {
          ForAudience = "some-audience.com",
          IdentifiedBy = "87IFSGFgPNtQNNuw0AtuLttP",
          IssuedBy = "paragonie.com",
          Subject = "test",
          NotExpired = true,
          ValidAt = true,
          ContainsClaim = "data"
        }
        local verified_claims = paseto.verify(public_key, token, claim_rules)
        assert.equal("table", type(verified_claims))
        assert.equal(#payload_claims, #verified_claims)
        assert.equal(payload_claims.data, verified_claims.data)
      end)

      it("should raise error 'Invalid claim rules format'", function()
        local token = paseto.sign(secret_key, payload_claims)
        local claim_rules = "invalid format"
        local verified_claims, err = paseto.verify(public_key, token, claim_rules)
        assert.equal(nil, verified_claims)
        assert.equal("Invalid claim rules format", err)
      end)

      it("should raise error 'Missing required claim 'required_claim''", function()
        local token = paseto.sign(secret_key, payload_claims)
        local claim_rules = { required_claim = "this is a signed message", myclaim = "validate this" }
        local verified_claims, err = paseto.verify(public_key, token, claim_rules)
        assert.equal(nil, verified_claims)
        assert.equal("Missing required claim 'required_claim'", err)
      end)

      it("should raise error 'Claim 'myclaim' does not match the expected value'", function()
        local token = paseto.sign(secret_key, payload_claims)
        local claim_rules = { data = "this is a signed message", myclaim = "invalid" }
        local verified_claims, err = paseto.verify(public_key, token, claim_rules)
        assert.equal(nil, verified_claims)
        assert.equal("Claim 'myclaim' does not match the expected value", err)
      end)

      it("should raise error 'Claim 'aud' does not match the expected value' when validating rule 'ForAudience'", function()
        local token = paseto.sign(secret_key, payload_claims)
        local claim_rules = { ForAudience = "some-other-audience.com" }
        local verified_claims, err = paseto.verify(public_key, token, claim_rules)
        assert.equal(nil, verified_claims)
        assert.equal("Claim 'aud' does not match the expected value", err)
      end)

      it("should raise error 'Missing required claim 'exp''", function()
        local token = paseto.sign(secret_key, {})
        local claim_rules = { NotExpired = true }
        local verified_claims, err = paseto.verify(public_key, token, claim_rules)
        assert.equal(nil, verified_claims)
        assert.equal("Missing required claim 'exp'", err)
      end)

      it("should raise error 'Token has expired'", function()
        payload_claims["exp"] = date(os.time()):addseconds(-1):fmt("${iso}%z")
        local token = paseto.sign(secret_key, payload_claims)
        local claim_rules = { NotExpired = true }
        local verified_claims, err = paseto.verify(public_key, token, claim_rules)
        assert.equal(nil, verified_claims)
        assert.equal("Token has expired", err)
      end)

      it("should raise error 'Token was issued in the future'", function()
        local future = date(os.time()):addminutes(10)
        payload_claims["iat"] = future:fmt("${iso}%z")
        payload_claims["nbf"] = future:fmt("${iso}%z")
        payload_claims["exp"] = future:fmt("${iso}%z")
        local token = paseto.sign(secret_key, payload_claims)
        local claim_rules = { ValidAt = true }
        local verified_claims, err = paseto.verify(public_key, token, claim_rules)
        assert.equal(nil, verified_claims)
        assert.equal("Token was issued in the future", err)
      end)

      it("should raise error 'Token cannot be used yet'", function()
        local now = date(os.time())
        local future = date(os.time()):addminutes(10)
        payload_claims["iat"] = now:fmt("${iso}%z")
        payload_claims["nbf"] = future:fmt("${iso}%z")
        payload_claims["exp"] = future:fmt("${iso}%z")
        local token = paseto.sign(secret_key, payload_claims)
        local claim_rules = { ValidAt = true }
        local verified_claims, err = paseto.verify(public_key, token, claim_rules)
        assert.equal(nil, verified_claims)
        assert.equal("Token cannot be used yet", err)
      end)

      it("should raise error 'Token has expired'", function()
        local now = date(os.time())
        local past = date(os.time()):addminutes(-10)
        payload_claims["iat"] = now:fmt("${iso}%z")
        payload_claims["nbf"] = now:fmt("${iso}%z")
        payload_claims["exp"] = past:fmt("${iso}%z")
        local token = paseto.sign(secret_key, payload_claims)
        local claim_rules = { ValidAt = true }
        local verified_claims, err = paseto.verify(public_key, token, claim_rules)
        assert.equal(nil, verified_claims)
        assert.equal("Token has expired", err)
      end)

      it("should raise error 'Missing required claim 'important_claim'", function()
        local token = paseto.sign(secret_key, payload_claims)
        local claim_rules = { ContainsClaim = "important_claim" }
        local verified_claims, err = paseto.verify(public_key, token, claim_rules)
        assert.equal(nil, verified_claims)
        assert.equal("Missing required claim 'important_claim'", err)
      end)

    end)

  end)

  describe("readme examples for the standard API", function()

    describe("v2.local example", function()

      it("should encrypt and decrypt", function()
        local key, payload_claims, token, footer_claims, claim_rules
        local extracted_footer_claims, extracted_footer, decrypted_claims, enforced_claims
        payload_claims = {
          iss = "paragonie.com",
          jti = "87IFSGFgPNtQNNuw0AtuLttP",
          aud = "some-audience.com",
          sub = "test",
          iat = "2018-01-01T00:00:00+00:00",
          nbf = "2018-01-01T00:00:00+00:00",
          exp = "2099-01-01T00:00:00+00:00",
          data = "this is a secret message"
        }
        footer_claims = { kid = "123456789" }
        claim_rules = {
          IssuedBy = "paragonie.com",
          IdentifiedBy = "87IFSGFgPNtQNNuw0AtuLttP",
          ForAudience = "some-audience.com",
          Subject = "test",
          NotExpired = true,
          ValidAt = true,
          ContainsClaim = "data"
        }

        -- generate symmetric key
        key = paseto.generate_symmetric_key()

        -- encrypt/decrypt without footer and without enforcing claim rules
        token = paseto.encrypt(key, payload_claims)
        decrypted_claims = paseto.decrypt(key, token)
        assert.equal(#payload_claims, #decrypted_claims)
        assert.equal(payload_claims.clientid, decrypted_claims.clientid)
        assert.equal(payload_claims.message, decrypted_claims.message)

        -- encrypt with footer
        token = paseto.encrypt(key, payload_claims, footer_claims)
        extracted_footer_claims, extracted_footer = paseto.extract_footer_claims(token)
        assert.equal(#footer_claims, #extracted_footer_claims)
        assert.equal(footer_claims.kid, extracted_footer_claims.kid)
        -- decrypt without enforcing claim rules
        decrypted_claims = paseto.decrypt(key, token, nil, extracted_footer)
        -- decrypt and enforce claim rules
        enforced_claims = paseto.decrypt(key, token, claim_rules, extracted_footer)
        assert.equal(#payload_claims, #decrypted_claims)
        assert.equal(#payload_claims, #enforced_claims)
        assert.equal(payload_claims.clientid, decrypted_claims.clientid)
        assert.equal(payload_claims.message, decrypted_claims.message)
      end)

    end)

    describe("v2.public example", function()

      it("should sign and verify", function()
        local secret_key, public_key, payload_claims, token, footer_claims, claim_rules
        local extracted_footer_claims, extracted_footer, verified_claims, enforced_claims
        payload_claims = {
          iss = "paragonie.com",
          jti = "87IFSGFgPNtQNNuw0AtuLttP",
          aud = "some-audience.com",
          sub = "test",
          iat = "2018-01-01T00:00:00+00:00",
          nbf = "2018-01-01T00:00:00+00:00",
          exp = "2099-01-01T00:00:00+00:00",
          data = "this is a signed message"
        }
        footer_claims = { kid = "123456789" }
        claim_rules = {
          IssuedBy = "paragonie.com",
          IdentifiedBy = "87IFSGFgPNtQNNuw0AtuLttP",
          ForAudience = "some-audience.com",
          Subject = "test",
          NotExpired = true,
          ValidAt = true,
          ContainsClaim = "data"
        }

        -- generate key pair
        secret_key, public_key = paseto.generate_asymmetric_secret_key()

        -- sign/verify without footer and without enforcing claim rules
        token = paseto.sign(secret_key, payload_claims)
        verified_claims = paseto.verify(public_key, token)
        assert.equal(#payload_claims, #verified_claims)
        assert.equal(payload_claims.clientid, verified_claims.clientid)
        assert.equal(payload_claims.message, verified_claims.message)

        -- sign with footer
        token = paseto.sign(secret_key, payload_claims, footer_claims)
        extracted_footer_claims, extracted_footer = paseto.extract_footer_claims(token)
        assert.equal(#footer_claims, #extracted_footer_claims)
        assert.equal(footer_claims.kid, extracted_footer_claims.kid)
        -- verify without enforcing claim rules
        verified_claims = paseto.verify(public_key, token, nil, extracted_footer)
        -- verify and enforce claim rules
        enforced_claims = paseto.verify(public_key, token, claim_rules, extracted_footer)
        assert.equal(#payload_claims, #verified_claims)
        assert.equal(#payload_claims, #enforced_claims)
        assert.equal(payload_claims.clientid, verified_claims.clientid)
        assert.equal(payload_claims.message, verified_claims.message)
      end)

    end)

  end)

end)
