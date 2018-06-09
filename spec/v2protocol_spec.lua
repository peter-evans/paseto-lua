local paseto = require "paseto"
local utils = require("utils")

describe("v2 protocol", function()

  describe("key generation", function()

    it("should generate a symmetric key", function()
      local symmetric = paseto.v2().generate_symmetric_key()
      assert.equal(paseto.v2().get_symmetric_key_byte_length(), #symmetric)
    end)

    it("should generate an asymmetric key", function()
      local asymmetric = paseto.v2().generate_asymmetric_secret_key()
      assert.equal(64, #asymmetric)
    end)

  end)

  describe("pre auth encode", function()

    it("should encode an empty array", function()
      assert.equal("0000000000000000", utils.tohex(paseto.v2().__pre_auth_encode()));
    end)

    it("should encode an array consisting of a single empty string", function()
      assert.equal("01000000000000000000000000000000", utils.tohex(paseto.v2().__pre_auth_encode("")));
    end)

    it("should encode an array consisting of empty strings", function()
      assert.equal("020000000000000000000000000000000000000000000000",
        utils.tohex(paseto.v2().__pre_auth_encode("", "")));
    end)

    it("should encode an array consisting of a single non-empty string", function()
      assert.equal("0100000000000000070000000000000050617261676f6e",
        utils.tohex(paseto.v2().__pre_auth_encode("Paragon")));
    end)

    it("should encode an array consisting of non-empty strings", function()
      assert.equal("0200000000000000070000000000000050617261676f6e0a00000000000000496e6974696174697665",
        utils.tohex(paseto.v2().__pre_auth_encode("Paragon", "Initiative")));
    end)

    it("should ensure that faked padding results in different prefixes", function()
      assert.equal("0100000000000000190000000000000050617261676f6e0a00000000000000496e6974696174697665",
        utils.tohex(paseto.v2().__pre_auth_encode(
            "Paragon" .. string.char(10) .. string.rep("\0", 7) .. "Initiative")));
    end)

  end)

  describe("validate and remove footer", function()
    local payload, footer, token

    setup(function()
      local luasodium = require("luasodium")
      payload = utils.base64_encode(luasodium.randombytes(30))
      footer = luasodium.randombytes(10)
      token = payload .. "." .. utils.base64_encode(footer, true)
    end)

    it("should validate and remove footer from token data", function()
      assert.equal(payload, paseto.v2().__validate_and_remove_footer(token, footer))
    end)

    it("should raise error 'Invalid message footer'", function()
      local validated, err = paseto.v2().__validate_and_remove_footer(token, "wrong")
      assert.equal(nil, validated)
      assert.equal("Invalid message footer", err)
    end)

  end)

  describe("authenticated encryption", function()

    local key, message, footer

    setup(function()
      key = paseto.v2().generate_symmetric_key()
      footer = "footer"
    end)

    describe("text", function()

      setup(function()
        message = "test"
      end)

      it("should encrypt and decrypt text without footer", function()
        local token = paseto.v2().encrypt(key, message)
        assert.equal("string", type(token))
        assert.equal("v2.local.", string.sub(token, 1, 9))

        local decrypted = paseto.v2().decrypt(key, token)
        assert.equal("string", type(decrypted))
        assert.equal(message, decrypted)
      end)

      it("should encrypt and decrypt text with footer", function()
        local token = paseto.v2().encrypt(key, message, footer)
        assert.equal("string", type(token))
        assert.equal("v2.local.", string.sub(token, 1, 9))

        local decrypted = paseto.v2().decrypt(key, token, footer)
        assert.equal("string", type(decrypted))
        assert.equal(message, decrypted)
      end)

      it("should raise error 'Invalid key size'", function()
        local token, err = paseto.v2().encrypt("\0", message)
        assert.equal(nil, token)
        assert.equal("Invalid key size", err)
      end)

      it("should raise error 'Invalid message header'", function()
        local decrypt, err = paseto.v2().decrypt(key, message)
        assert.equal(nil, decrypt)
        assert.equal("Invalid message header", err)
      end)

      it("should raise error 'Message forged'", function()
        local decrypt, err = paseto.v2().decrypt(key, "v2.local." .. message)
        assert.equal(nil, decrypt)
        assert.equal("Message forged", err)
      end)

      it("should raise error 'Message forged'", function()
        local token = paseto.v2().encrypt(key, message)
        local decrypt, err = paseto.v2().decrypt("\0", token)
        assert.equal(nil, decrypt)
        assert.equal("Message forged", err)
      end)

      it("should raise error 'Invalid message footer'", function()
        local token = paseto.v2().encrypt(key, message)
        local decrypt, err = paseto.v2().decrypt(key, token, "footer")
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
        local token = paseto.v2().encrypt(key, message)
        assert.equal("string", type(token))
        assert.equal("v2.local.", string.sub(token, 1, 9))

        local decrypted = paseto.v2().decrypt(key, token)
        assert.equal("string", type(decrypted))
        assert.equal(message, decrypted)
      end)

      it("should encrypt and decrypt json with footer", function()
        local token = paseto.v2().encrypt(key, message, footer)
        assert.equal("string", type(token))
        assert.equal("v2.local.", string.sub(token, 1, 9))

        local decrypted = paseto.v2().decrypt(key, token, footer)
        assert.equal("string", type(decrypted))
        assert.equal(message, decrypted)
      end)

    end)

  end)

  describe("signing", function()

    local secret_key, public_key, message, footer

    setup(function()
      secret_key = paseto.v2().generate_asymmetric_secret_key()
      public_key = string.sub(secret_key, 33, 64)
      footer = "footer"
    end)

    describe("text", function()

      setup(function()
        message = "test"
      end)

      it("should sign and verify text successfully without footer", function()
        local token = paseto.v2().sign(secret_key, message)
        assert.equal("string", type(token))
        assert.equal("v2.public.", string.sub(token, 1, 10))

        local verified = paseto.v2().verify(public_key, token)
        assert.equal("string", type(verified))
        assert.equal(message, verified)
      end)

      it("should sign and verify text successfully with footer", function()
        local token = paseto.v2().sign(secret_key, message, footer)
        assert.equal("string", type(token))
        assert.equal("v2.public.", string.sub(token, 1, 10))

        local verified = paseto.v2().verify(public_key, token, footer)
        assert.equal("string", type(verified))
        assert.equal(message, verified)
      end)

      it("should raise error 'Invalid message header'", function()
        local verify, err = paseto.v2().verify(public_key, message)
        assert.equal(nil, verify)
        assert.equal("Invalid message header", err)
      end)

      it("should raise error 'Invalid signature for this message'", function()
        local verify, err = paseto.v2().verify(public_key, "v2.public." .. message)
        assert.equal(nil, verify)
        assert.equal("Invalid signature for this message", err)
      end)

      it("should raise error 'Invalid message footer'", function()
        local token = paseto.v2().sign(secret_key, message)
        local verify, err = paseto.v2().verify(public_key, token, "footer")
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
        local token = paseto.v2().sign(secret_key, message)
        assert.equal("string", type(token))
        assert.equal("v2.public.", string.sub(token, 1, 10))

        local verified = paseto.v2().verify(public_key, token)
        assert.equal("string", type(verified))
        assert.equal(message, verified)
      end)

      it("should sign and verify json successfully with footer", function()
        local token = paseto.v2().sign(secret_key, message, footer)
        assert.equal("string", type(token))
        assert.equal("v2.public.", string.sub(token, 1, 10))

        local verified = paseto.v2().verify(public_key, token, footer)
        assert.equal("string", type(verified))
        assert.equal(message, verified)
      end)

    end)

  end)

end)
