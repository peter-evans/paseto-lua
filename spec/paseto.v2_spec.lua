local paseto = require "paseto.v2"
local basexx = require "basexx"

describe("v2 protocol", function()

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

  describe("readme examples for the standard API", function()

    describe("v2.local example", function()

      it("should encrypt and decrypt", function()
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
        assert.equal(#payload_claims, #decrypted_claims)
        assert.equal(payload_claims.clientid, decrypted_claims.clientid)
        assert.equal(payload_claims.message, decrypted_claims.message)

        -- encrypt/decrypt with footer
        token = paseto.encrypt(key, payload_claims, footer_claims)
        extracted_footer_claims, extracted_footer = paseto.extract_footer_claims(token)
        assert.equal(#footer_claims, #extracted_footer_claims)
        assert.equal(footer_claims.kid, extracted_footer_claims.kid)
        decrypted_claims = paseto.decrypt(key, token, extracted_footer)
        assert.equal(#payload_claims, #decrypted_claims)
        assert.equal(payload_claims.clientid, decrypted_claims.clientid)
        assert.equal(payload_claims.message, decrypted_claims.message)
      end)

    end)

    describe("v2.public example", function()

      it("should sign and verify", function()
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
        assert.equal(#payload_claims, #verified_claims)
        assert.equal(payload_claims.clientid, verified_claims.clientid)
        assert.equal(payload_claims.message, verified_claims.message)

        -- sign/verify with footer
        token = paseto.sign(secret_key, payload_claims, footer_claims)
        extracted_footer_claims, extracted_footer = paseto.extract_footer_claims(token)
        assert.equal(#footer_claims, #extracted_footer_claims)
        assert.equal(footer_claims.kid, extracted_footer_claims.kid)
        verified_claims = paseto.verify(public_key, token, extracted_footer)
        assert.equal(#payload_claims, #verified_claims)
        assert.equal(payload_claims.clientid, verified_claims.clientid)
        assert.equal(payload_claims.message, verified_claims.message)
      end)

    end)

  end)

end)
