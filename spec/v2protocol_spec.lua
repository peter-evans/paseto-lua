local paseto = require "paseto"

describe("v2 protocol", function()

  describe("key generation", function()

    it("should generate a symmetric key'", function()
      local symmetric = paseto.v2().generate_symmetric_key()
      assert.equal(paseto.v2().get_symmetric_key_byte_length(), string.len(symmetric))
    end)

    it("should generate an asymmetric key'", function()
      local asymmetric = paseto.v2().generate_asymmetric_secret_key()
      assert.equal(64, string.len(asymmetric))
    end)

  end)

end)
