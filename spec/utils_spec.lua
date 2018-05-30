local utils = require "utils"

describe("utils", function()

  describe("hex encode/decode", function()

    it("should hex encode and decode", function()
      local expected = "expected result 0123456789"
      assert.equal(expected, utils.fromhex(utils.tohex(expected)));
    end)

  end)

  describe("pre auth encode", function()

    it("should encode an empty array", function()
      assert.equal("0000000000000000", utils.tohex(utils.pre_auth_encode()));
    end)

    it("should encode an array consisting of a single empty string", function()
      assert.equal("01000000000000000000000000000000", utils.tohex(utils.pre_auth_encode("")));
    end)

    it("should encode an array consisting of empty strings", function()
      assert.equal("020000000000000000000000000000000000000000000000", utils.tohex(utils.pre_auth_encode("", "")));
    end)

    it("should encode an array consisting of a single non-empty string", function()
      assert.equal("0100000000000000070000000000000050617261676f6e", utils.tohex(utils.pre_auth_encode("Paragon")));
    end)

    it("should encode an array consisting of non-empty strings", function()
      assert.equal("0200000000000000070000000000000050617261676f6e0a00000000000000496e6974696174697665",
        utils.tohex(utils.pre_auth_encode("Paragon", "Initiative")));
    end)

    it("should ensure that faked padding results in different prefixes", function()
      assert.equal("0100000000000000190000000000000050617261676f6e0a00000000000000496e6974696174697665",
        utils.tohex(utils.pre_auth_encode("Paragon" .. string.char(10) .. "\0\0\0\0\0\0\0" .. "Initiative")));
    end)

  end)

end)
