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

end)
