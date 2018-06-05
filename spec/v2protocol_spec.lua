local paseto = require "paseto"

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

      it("should raise error 'Invalid message header'", function()
        local decrypt = function()
          paseto.v2().decrypt(key, message)
        end
        assert.has_error(decrypt, "Invalid message header")
      end)

      it("should raise error 'bad nonce size'", function()
        local decrypt = function()
          paseto.v2().decrypt(key, "v2.local." .. message)
        end
        assert.has_error(decrypt, "bad nonce size")
      end)

      it("should raise error 'Invalid message footer'", function()
        local token = paseto.v2().encrypt(key, message)
        local decrypt = function()
          paseto.v2().decrypt(key, token, "footer")
        end
        assert.has_error(decrypt, "Invalid message footer")
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
      local key_pair = paseto.v2().generate_asymmetric_secret_key()
      secret_key = string.sub(key_pair, 1, 32)
      public_key = string.sub(key_pair, 33, 64)
      footer = "footer"
    end)

    describe("text", function()

      setup(function()
        message = "test"
      end)

      it("should sign and verify text successfully without footer", function()
        local token = paseto.v2().sign(secret_key, public_key, message)
        assert.equal("string", type(token))
        assert.equal("v2.public.", string.sub(token, 1, 10))

        local verified = paseto.v2().verify(public_key, token)
        assert.equal("string", type(verified))
        assert.equal(message, verified)
      end)

      it("should sign and verify text successfully with footer", function()
        local token = paseto.v2().sign(secret_key, public_key, message, footer)
        assert.equal("string", type(token))
        assert.equal("v2.public.", string.sub(token, 1, 10))

        local verified = paseto.v2().verify(public_key, token, footer)
        assert.equal("string", type(verified))
        assert.equal(message, verified)
      end)

      it("should raise error 'Invalid message header'", function()
        local verify = function()
          paseto.v2().verify(public_key, message)
        end
        assert.has_error(verify, "Invalid message header")
      end)

      it("should raise error 'bad signature size'", function()
        local verify = function()
          paseto.v2().verify(public_key, "v2.public." .. message)
        end
        assert.has_error(verify, "bad signature size")
      end)

      it("should raise error 'Invalid message footer'", function()
        local token = paseto.v2().sign(secret_key, public_key, message)
        local verify = function()
          paseto.v2().verify(public_key, token, "footer")
        end
        assert.has_error(verify, "Invalid message footer")
      end)

    end)

    describe("json", function()

      setup(function()
        message = "{ \"data\": \"this is a signed message\", \"expires\": \"" ..
          os.date("%Y") .. "-01-01T00:00:00+00:00\" }"
      end)

      it("should sign and verify json successfully without footer", function()
        local token = paseto.v2().sign(secret_key, public_key, message)
        assert.equal("string", type(token))
        assert.equal("v2.public.", string.sub(token, 1, 10))

        local verified = paseto.v2().verify(public_key, token)
        assert.equal("string", type(verified))
        assert.equal(message, verified)
      end)

      it("should sign and verify json successfully with footer", function()
        local token = paseto.v2().sign(secret_key, public_key, message, footer)
        assert.equal("string", type(token))
        assert.equal("v2.public.", string.sub(token, 1, 10))

        local verified = paseto.v2().verify(public_key, token, footer)
        assert.equal("string", type(verified))
        assert.equal(message, verified)
      end)

    end)

  end)

end)
