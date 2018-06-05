local paseto = require "paseto"

describe("v2 protocol official test vectors", function()

  local symmetricKey

  setup(function()
    symmetricKey = require("utils").fromhex("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
  end)

  describe("official test vectors", function()

    local nonce, nonce2, footer, message

    setup(function()
        nonce = string.rep("\0", 24)
        -- nonce2 = sodium_crypto_generichash("Paragon Initiative Enterprises, LLC", "", 24)
        nonce2 = require("utils").fromhex("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b")
        footer = ""
        --message = \json_encode(['data' => 'this is a signed message', 'exp' => '2019-01-01T00:00:00+00:00']);
        message = "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}"

    end)

    it("should pass 'Test Vector 2-E-1'", function()
      assert.equal(
        "v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ", 
        paseto.v2().__encrypt(symmetricKey, message, footer, nonce))
    end)

    it("should pass 'Test Vector 2-E-3'", function()
      assert.equal(
        "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-O5xRBN076fSDPo5xUCPpBA", 
        paseto.v2().__encrypt(symmetricKey, message, footer, nonce2))
    end)

  end)

end)
