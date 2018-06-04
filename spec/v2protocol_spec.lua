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

    local key, footer, message

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

end)
