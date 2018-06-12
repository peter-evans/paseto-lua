local paseto = require "paseto.v2"
local basexx = require "basexx"

describe("v2 protocol official test vectors", function()

  local symmetric_key, secret_key

  setup(function()
    symmetric_key = basexx.from_hex("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
    secret_key = basexx.from_hex("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
  end)

  describe("official test vectors", function()

    local nonce1, nonce2, footer1, footer2, message1, message2

    setup(function()
        nonce1 = string.rep("\0", 24)
        nonce2 = basexx.from_hex("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b")
        footer1 = ""
        footer2 = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}"
        message1 = "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}"
        message2 = "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}"

    end)

    it("should pass 'Test Vector 2-E-1'", function()
      assert.equal(
        "v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ",
        paseto.__encrypt(symmetric_key, message1, footer1, nonce1))
    end)

    it("should pass 'Test Vector 2-E-2'", function()
      assert.equal(
        "v2.local.CH50H-HM5tzdK4kOmQ8KbIvrzJfjYUGuu5Vy9ARSFHy9owVDMYg3-8rwtJZQjN9ABHb2njzFkvpr5cOYuRyt7CRXnHt42L5yZ7siD-4l-FoNsC7J2OlvLlIwlG06mzQVunrFNb7Z3_CHM0PK5w",
        paseto.__encrypt(symmetric_key, message2, footer1, nonce1))
    end)

    it("should pass 'Test Vector 2-E-3'", function()
      assert.equal(
        "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-O5xRBN076fSDPo5xUCPpBA",
        paseto.__encrypt(symmetric_key, message1, footer1, nonce2))
    end)

    it("should pass 'Test Vector 2-E-4'", function()
      assert.equal(
        "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DPbIxtjGvNRAwsLK7LcV8oQ",
        paseto.__encrypt(symmetric_key, message2, footer1, nonce2))
    end)

    it("should pass 'Test Vector 2-E-5'", function()
      assert.equal(
        "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        paseto.__encrypt(symmetric_key, message1, footer2, nonce2))
    end)

    it("should pass 'Test Vector 2-E-6'", function()
      assert.equal(
        "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        paseto.__encrypt(symmetric_key, message2, footer2, nonce2))
    end)

    it("should pass 'Test Vector 2-S-1'", function()
      assert.equal(
        "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGntTu7Dz9J2IF23d1M7-9lH9xiqdGyJNvzp4angPW5Esc7C5huy_M8I8_DjJK2ZXC2SUYuOFM-Q_5Cw",
        paseto.sign(secret_key, message1, footer1))
    end)

    it("should pass 'Test Vector 2-S-2'", function()
      assert.equal(
        "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        paseto.sign(secret_key, message1, footer2))
    end)

  end)

end)
