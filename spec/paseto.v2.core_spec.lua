local paseto = require "paseto.v2.core"
local basexx = require "basexx"

describe("v2 protocol", function()

  describe("key generation", function()

    it("should generate a symmetric key", function()
      local symmetric = paseto.generate_symmetric_key()
      assert.equal(paseto.SYMMETRIC_KEY_BYTES, #symmetric)
    end)

    it("should generate an asymmetric key", function()
      local secret_key, public_key = paseto.generate_asymmetric_secret_key()
      assert.equal(paseto.ASYMMETRIC_SECRET_KEY_BYTES, #secret_key)
      assert.equal(paseto.ASYMMETRIC_PUBLIC_KEY_BYTES, #public_key)
    end)

  end)

  describe("pre auth encode", function()

    it("should encode an empty array", function()
      assert.equal("0000000000000000", basexx.to_hex(paseto.__pre_auth_encode()));
    end)

    it("should encode an array consisting of a single empty string", function()
      assert.equal("01000000000000000000000000000000", basexx.to_hex(paseto.__pre_auth_encode("")));
    end)

    it("should encode an array consisting of empty strings", function()
      assert.equal("020000000000000000000000000000000000000000000000",
        basexx.to_hex(paseto.__pre_auth_encode("", "")));
    end)

    it("should encode an array consisting of a single non-empty string", function()
      assert.equal(string.upper("0100000000000000070000000000000050617261676f6e"),
        basexx.to_hex(paseto.__pre_auth_encode("Paragon")));
    end)

    it("should encode an array consisting of non-empty strings", function()
      assert.equal(string.upper("0200000000000000070000000000000050617261676f6e0a00000000000000496e6974696174697665"),
        basexx.to_hex(paseto.__pre_auth_encode("Paragon", "Initiative")));
    end)

    it("should ensure that faked padding results in different prefixes", function()
      assert.equal(string.upper("0100000000000000190000000000000050617261676f6e0a00000000000000496e6974696174697665"),
        basexx.to_hex(paseto.__pre_auth_encode(
            "Paragon" .. string.char(10) .. string.rep("\0", 7) .. "Initiative")));
    end)

  end)

  describe("validate and remove footer", function()
    local payload, footer, token

    setup(function()
      local luasodium = require("luasodium")
      payload = basexx.to_url64(luasodium.randombytes(30))
      footer = luasodium.randombytes(10)
      token = payload .. "." .. basexx.to_url64(footer)
    end)

    it("should validate and remove footer from token data", function()
      assert.equal(payload, paseto.__validate_and_remove_footer(token, footer))
    end)

    it("should raise error 'Invalid message footer'", function()
      local validated, err = paseto.__validate_and_remove_footer(token, "wrong")
      assert.equal(nil, validated)
      assert.equal("Invalid message footer", err)
    end)

  end)

  describe("extract version and purpose", function()
    local key, secret_key, message

    setup(function()
      key = paseto.generate_symmetric_key()
      secret_key = paseto.generate_asymmetric_secret_key()
      message = "test"
    end)

    it("should extract the version and purpose from a 'local' token", function()
      local token = paseto.encrypt(key, message)
      local version, purpose = paseto.extract_version_purpose(token)
      assert.equal("v2", version)
      assert.equal("local", purpose)
    end)

    it("should extract the version and purpose from a 'public' token", function()
      local token = paseto.sign(secret_key, message)
      local version, purpose = paseto.extract_version_purpose(token)
      assert.equal("v2", version)
      assert.equal("public", purpose)
    end)

    it("should raise error 'Invalid token format' for malformed tokens", function()
      local version, purpose, err = paseto.extract_version_purpose("v2.public")
      assert.equal(nil, version)
      assert.equal(nil, purpose)
      assert.equal("Invalid token format", err)
    end)

    it("should raise error 'Invalid token format' for malformed tokens", function()
      local version, purpose, err = paseto.extract_version_purpose("v2.public.payload.footer.malformed")
      assert.equal(nil, version)
      assert.equal(nil, purpose)
      assert.equal("Invalid token format", err)
    end)

    it("should raise error 'Invalid token format' for nil values", function()
      local version, purpose, err = paseto.extract_version_purpose()
      assert.equal(nil, version)
      assert.equal(nil, purpose)
      assert.equal("Invalid token format", err)
    end)

  end)

  describe("extract footer", function()
    local key, secret_key, message, footer

    setup(function()
      key = paseto.generate_symmetric_key()
      secret_key = paseto.generate_asymmetric_secret_key()
      message = "test"
      footer = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}"
    end)

    it("should extract the footer claims from a 'local' token", function()
      local token = paseto.encrypt(key, message, footer)
      local extracted_footer = paseto.extract_footer(token)
      assert.equal(footer, extracted_footer)
    end)

    it("should extract the footer claims from a 'public' token", function()
      local token = paseto.sign(secret_key, message, footer)
      local extracted_footer = paseto.extract_footer(token)
      assert.equal(footer, extracted_footer)
    end)

    it("should return an empty string for tokens without a footer", function()
      local token = paseto.sign(secret_key, message)
      local extracted_footer = paseto.extract_footer(token)
      assert.equal("", extracted_footer)
    end)

    it("should raise error 'Invalid token format' for malformed tokens", function()
      local extracted_footer, err = paseto.extract_footer("v2.public")
      assert.equal(nil, extracted_footer)
      assert.equal("Invalid token format", err)
    end)

    it("should raise error 'Invalid token format' for malformed tokens", function()
      local extracted_footer, err = paseto.extract_footer("v2.public.payload.footer.malformed")
      assert.equal(nil, extracted_footer)
      assert.equal("Invalid token format", err)
    end)

    it("should raise error 'Invalid token format' for nil values", function()
      local extracted_footer, err = paseto.extract_footer()
      assert.equal(nil, extracted_footer)
      assert.equal("Invalid token format", err)
    end)

  end)

  describe("authenticated encryption", function()

    local key, message, footer

    setup(function()
      key = paseto.generate_symmetric_key()
      footer = "footer"
    end)

    describe("text", function()

      setup(function()
        message = "test"
      end)

      it("should encrypt and decrypt text without footer", function()
        local token = paseto.encrypt(key, message)
        assert.equal("string", type(token))
        assert.equal("v2.local.", string.sub(token, 1, 9))

        local decrypted = paseto.decrypt(key, token)
        assert.equal("string", type(decrypted))
        assert.equal(message, decrypted)
      end)

      it("should encrypt and decrypt text with footer", function()
        local token = paseto.encrypt(key, message, footer)
        assert.equal("string", type(token))
        assert.equal("v2.local.", string.sub(token, 1, 9))

        local decrypted = paseto.decrypt(key, token, footer)
        assert.equal("string", type(decrypted))
        assert.equal(message, decrypted)
      end)

      it("should raise error 'Invalid key size'", function()
        local token, err = paseto.encrypt("\0", message)
        assert.equal(nil, token)
        assert.equal("Invalid key size", err)
      end)

      it("should raise error 'Invalid message header'", function()
        local decrypt, err = paseto.decrypt(key, message)
        assert.equal(nil, decrypt)
        assert.equal("Invalid message header", err)
      end)

      it("should raise error 'Message forged'", function()
        local decrypt, err = paseto.decrypt(key, "v2.local." .. message)
        assert.equal(nil, decrypt)
        assert.equal("Message forged", err)
      end)

      it("should raise error 'Message forged'", function()
        local token = paseto.encrypt(key, message)
        local decrypt, err = paseto.decrypt("\0", token)
        assert.equal(nil, decrypt)
        assert.equal("Message forged", err)
      end)

      it("should raise error 'Invalid message footer'", function()
        local token = paseto.encrypt(key, message)
        local decrypt, err = paseto.decrypt(key, token, "footer")
        assert.equal(nil, decrypt)
        assert.equal("Invalid message footer", err)
      end)

    end)

    describe("json", function()

      setup(function()
        message = "{ \"data\": \"this is a signed message\", \"expires\": \"" ..
          os.date("%Y") .. "-01-01T00:00:00+00:00\" }"
      end)

      it("should encrypt and decrypt json without footer", function()
        local token = paseto.encrypt(key, message)
        assert.equal("string", type(token))
        assert.equal("v2.local.", string.sub(token, 1, 9))

        local decrypted = paseto.decrypt(key, token)
        assert.equal("string", type(decrypted))
        assert.equal(message, decrypted)
      end)

      it("should encrypt and decrypt json with footer", function()
        local token = paseto.encrypt(key, message, footer)
        assert.equal("string", type(token))
        assert.equal("v2.local.", string.sub(token, 1, 9))

        local decrypted = paseto.decrypt(key, token, footer)
        assert.equal("string", type(decrypted))
        assert.equal(message, decrypted)
      end)

    end)

  end)

  describe("signing", function()

    local secret_key, public_key, message, footer

    setup(function()
      secret_key = paseto.generate_asymmetric_secret_key()
      public_key = string.sub(secret_key, 33, 64)
      footer = "footer"
    end)

    describe("text", function()

      setup(function()
        message = "test"
      end)

      it("should sign and verify text successfully without footer", function()
        local token = paseto.sign(secret_key, message)
        assert.equal("string", type(token))
        assert.equal("v2.public.", string.sub(token, 1, 10))

        local verified = paseto.verify(public_key, token)
        assert.equal("string", type(verified))
        assert.equal(message, verified)
      end)

      it("should sign and verify text successfully with footer", function()
        local token = paseto.sign(secret_key, message, footer)
        assert.equal("string", type(token))
        assert.equal("v2.public.", string.sub(token, 1, 10))

        local verified = paseto.verify(public_key, token, footer)
        assert.equal("string", type(verified))
        assert.equal(message, verified)
      end)

      it("should raise error 'Invalid message header'", function()
        local verify, err = paseto.verify(public_key, message)
        assert.equal(nil, verify)
        assert.equal("Invalid message header", err)
      end)

      it("should raise error 'Invalid signature for this message'", function()
        local verify, err = paseto.verify(public_key, "v2.public." .. message)
        assert.equal(nil, verify)
        assert.equal("Invalid signature for this message", err)
      end)

      it("should raise error 'Invalid message footer'", function()
        local token = paseto.sign(secret_key, message)
        local verify, err = paseto.verify(public_key, token, "footer")
        assert.equal(nil, verify)
        assert.equal("Invalid message footer", err)
      end)

    end)

    describe("json", function()

      setup(function()
        message = "{ \"data\": \"this is a signed message\", \"expires\": \"" ..
          os.date("%Y") .. "-01-01T00:00:00+00:00\" }"
      end)

      it("should sign and verify json successfully without footer", function()
        local token = paseto.sign(secret_key, message)
        assert.equal("string", type(token))
        assert.equal("v2.public.", string.sub(token, 1, 10))

        local verified = paseto.verify(public_key, token)
        assert.equal("string", type(verified))
        assert.equal(message, verified)
      end)

      it("should sign and verify json successfully with footer", function()
        local token = paseto.sign(secret_key, message, footer)
        assert.equal("string", type(token))
        assert.equal("v2.public.", string.sub(token, 1, 10))

        local verified = paseto.verify(public_key, token, footer)
        assert.equal("string", type(verified))
        assert.equal(message, verified)
      end)

    end)

  end)

  describe("readme examples for the core API", function()

    describe("v2.local example", function()

      it("should encrypt and decrypt", function()
        local key, message, token, footer, extracted_footer, decrypted
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
        extracted_footer = paseto.extract_footer(token)
        decrypted = paseto.decrypt(key, token, extracted_footer)
        assert.equal(message, decrypted)
      end)

    end)

    describe("v2.public example", function()

      it("should sign and verify", function()
        local secret_key, public_key, message, token, footer, extracted_footer, verified
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
        extracted_footer = paseto.extract_footer(token)
        verified = paseto.verify(public_key, token, extracted_footer)
        assert.equal(message, verified)
      end)

    end)

  end)

end)
