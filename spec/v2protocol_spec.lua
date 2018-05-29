local paseto = require "paseto"

describe("v2 protocol", function()

  describe("key generation", function()

    it("should generate a symmetric key'", function()
      local symmetric = paseto.v2().generate_symmetric_key()
      assert.equal(paseto.v2().get_symmetric_key_byte_length(), string.len(symmetric))
    end)

  end)

end)
