local utils = require "utils"

describe("utils", function()

  describe("hex encode/decode", function()

    it("should hex encode and decode", function()
      local expected = "expected result 0123456789"
      assert.equal(expected, utils.fromhex(utils.tohex(expected)));
    end)

  end)

  describe("pre auth encode", function()

    it("should generate a symmetric key", function()
      local encoded = utils.pre_auth_encode("Paragon")
      local expected = utils.tohex(utils.fromhex(utils.tohex(encoded)))
      assert.equal("0100000000000000070000000000000050617261676f6e", expected);
    end)

  end)

end)
