local paseto = require "paseto"

describe("paseto", function()

  describe("v2 protocol", function()

    it("should return the v2 protocol module", function()
      assert.truthy(paseto.v2())
    end)

  end)

end)
