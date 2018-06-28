local paseto = require "paseto.v2"

describe("v2 protocol", function()

  describe("extract footer claims", function()
    local key, secret_key, message, kid, footer

    setup(function()
      key = paseto.generate_symmetric_key()
      secret_key = paseto.generate_asymmetric_secret_key()
      message = "test"
      kid = "zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"
      footer = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}"
    end)

    it("should extract the footer claims from a 'local' token", function()
      local token = paseto.encrypt(key, message, footer)
      local footer_claims = paseto.extract_footer_claims(token)
      assert.equal("table", type(footer_claims))
      assert.equal(kid, footer_claims.kid)
    end)

    it("should extract the footer claims from a 'public' token", function()
      local token = paseto.sign(secret_key, message, footer)
      local footer_claims = paseto.extract_footer_claims(token)
      assert.equal("table", type(footer_claims))
      assert.equal(kid, footer_claims.kid)
    end)

    it("should return an empty table for tokens without a footer", function()
      local token = paseto.sign(secret_key, message)
      local footer_claims = paseto.extract_footer_claims(token)
      assert.equal("table", type(footer_claims))
      assert.equal(#{}, #footer_claims)
    end)

    it("should raise error 'Invalid token format' for malformed tokens", function()
      local footer_claims, err = paseto.extract_footer_claims("v2.public")
      assert.equal(nil, footer_claims)
      assert.equal("Invalid token format", err)
    end)

    it("should raise error 'Invalid token format' for nil values", function()
      local footer_claims, err = paseto.extract_footer_claims()
      assert.equal(nil, footer_claims)
      assert.equal("Invalid token format", err)
    end)

  end)

  describe("readme examples", function()

    describe("v2.local example", function()

      it("should encrypt and decrypt", function()
        local key, message, token, footer, decrypted
        message = "my secret message"
        footer = "my footer"

        -- generate symmetric key
        key = paseto.generate_symmetric_key()

        -- encrypt/decrypt without footer
        token = paseto.encrypt(key, message)
        decrypted = paseto.decrypt(key, token)
        assert.equal(message, decrypted)

        -- encrypt/decrypt with footer
        token = paseto.encrypt(key, message, footer)
        decrypted = paseto.decrypt(key, token, footer)
        assert.equal(message, decrypted)
      end)

    end)

    describe("v2.public example", function()

      it("should sign and verify", function()
        local secret_key, public_key, message, token, footer, verified
        message = "my secret message"
        footer = "my footer"

        -- generate key pair
        secret_key, public_key = paseto.generate_asymmetric_secret_key()

        -- sign/verify without footer
        token = paseto.sign(secret_key, message)
        verified = paseto.verify(public_key, token)
        assert.equal(message, verified)

        -- sign/verify with footer
        token = paseto.sign(secret_key, message, footer)
        verified = paseto.verify(public_key, token, footer)
        assert.equal(message, verified)
      end)

    end)

  end)

end)
