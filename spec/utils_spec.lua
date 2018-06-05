local utils = require "utils"

describe("utils", function()

  describe("hex encode/decode", function()

    it("should hex encode and decode", function()
      local expected = "expected result 0123456789"
      assert.equal(expected, utils.fromhex(utils.tohex(expected)));
    end)

  end)

  describe("base64 encode/decode", function()

    it("should encode and decode", function()
      assert.equal(utils.base64_encode(""), "")
      assert.equal(utils.base64_encode("f"), "Zg==")
      assert.equal(utils.base64_encode("fo"), "Zm8=")
      assert.equal(utils.base64_encode("foo"), "Zm9v")
      assert.equal(utils.base64_decode("Zg=="), "f")
      assert.equal(utils.base64_decode("Zm8="), "fo")
      assert.equal(utils.base64_decode("Zm9v"), "foo")
    end)

    it("should encode and decode with no padding", function()
      assert.equal(utils.base64_encode("", true), "")
      assert.equal(utils.base64_encode("f", true), "Zg")
      assert.equal(utils.base64_encode("fo", true), "Zm8")
      assert.equal(utils.base64_encode("foo", true), "Zm9v")
      assert.equal(utils.base64_decode("Zg"), "f")
      assert.equal(utils.base64_decode("Zm8"), "fo")
      assert.equal(utils.base64_decode("Zm9v"), "foo")
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
        utils.tohex(utils.pre_auth_encode("Paragon" .. string.char(10) .. string.rep("\0", 7) .. "Initiative")));
    end)

  end)

  describe("validate and remove footer", function()
    local payload, footer, token

    setup(function()
      local luanacha = require("luanacha")
      payload = utils.base64_encode(luanacha.randombytes(30))
      footer = luanacha.randombytes(10)
      token = payload .. "." .. utils.base64_encode(footer, true)
    end)

    it("should validate and remove footer from token data", function()
      assert.equal(payload, utils.validate_and_remove_footer(token, footer))
    end)

    it("should raise error 'Invalid message footer'", function()
      local validate_and_remove_footer = function()
        utils.validate_and_remove_footer(token, "wrong")
      end
      assert.has_error(validate_and_remove_footer, "Invalid message footer")
    end)

  end)

end)
