local paseto = require "paseto"

describe("v2 protocol", function()


  describe("key generation", function()

    it("should generate a symmetric key", function()
      local symmetric = paseto.v2().generate_symmetric_key()
      assert.equal(paseto.v2().get_symmetric_key_byte_length(), #symmetric)
    end)

    it("should generate an asymmetric key", function()
      local asymmetric = paseto.v2().generate_asymmetric_secret_key()
      assert.equal(64, string.len(asymmetric))
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
        local nonce, cipher = paseto.v2().encrypt(key, message)

      end)      
    end)

  end)

end)
