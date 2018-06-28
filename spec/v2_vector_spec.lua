local paseto = require "paseto.v2.core"
local basexx = require "basexx"

describe("v2 protocol official test vectors", function()

  local symmetric_key, null_key, full_key, secret_key
  local message1, message2, message3, footer1, footer2, nonce1, nonce2

  setup(function()
    symmetric_key = basexx.from_hex("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
    null_key = string.rep("\0", 32)
    full_key = basexx.from_hex(string.rep("ff", 32))
    secret_key = basexx.from_hex("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
    message1 = "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}"
    message2 = "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}"
    message3 = "{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}"
    footer1 = ""
    footer2 = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}"
    nonce1 = string.rep("\0", 24)
    nonce2 = basexx.from_hex("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b")
  end)

  describe("official test vectors", function()

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

  describe("encrypt test vectors", function()

    it("should pass 'Test Vector 2E-1-1'", function()
      assert.equal(
        "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNUtKpdy5KXjKfpSKrOlqQvQ",
        paseto.__encrypt(null_key, "", "", nonce1))
    end)

    it("should pass 'Test Vector 2E-1-2'", function()
      assert.equal(
        "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNSOvpveyCsjPYfe9mtiJDVg",
        paseto.__encrypt(full_key, "", "", nonce1))
    end)

    it("should pass 'Test Vector 2E-1-3'", function()
      assert.equal(
        "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNkIWACdHuLiJiW16f2GuGYA",
        paseto.__encrypt(symmetric_key, "", "", nonce1))
    end)

    it("should pass 'Test Vector 2E-2-1'", function()
      assert.equal(
        "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNfzz6yGkE4ZxojJAJwKLfvg.Q3VvbiBBbHBpbnVz",
        paseto.__encrypt(null_key, "", "Cuon Alpinus", nonce1))
    end)

    it("should pass 'Test Vector 2E-2-2'", function()
      assert.equal(
        "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNJbTJxAGtEg4ZMXY9g2LSoQ.Q3VvbiBBbHBpbnVz",
        paseto.__encrypt(full_key, "", "Cuon Alpinus", nonce1))
    end)

    it("should pass 'Test Vector 2E-2-3'", function()
      assert.equal(
        "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNreCcZAS0iGVlzdHjTf2ilg.Q3VvbiBBbHBpbnVz",
        paseto.__encrypt(symmetric_key, "", "Cuon Alpinus", nonce1))
    end)

    it("should pass 'Test Vector 2E-3-1'", function()
      assert.equal(
        "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSvu6cB-KuR4wR9uDMjd45cPiOF0zxb7rrtOB5tRcS7dWsFwY4ONEuL5sWeunqHC9jxU0",
        paseto.__encrypt(null_key, "Love is stronger than hate or fear", "", nonce1))
    end)

    it("should pass 'Test Vector 2E-3-2'", function()
      assert.equal(
        "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSjvSia2-chHyMi4LtHA8yFr1V7iZmKBWqzg5geEyNAAaD6xSEfxoET1xXqahe1jqmmPw",
        paseto.__encrypt(full_key, "Love is stronger than hate or fear", "", nonce1))
    end)

    it("should pass 'Test Vector 2E-3-3'", function()
      assert.equal(
        "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSXlvv8MsrNZs3vTSnGQG4qRM9ezDl880jFwknSA6JARj2qKhDHnlSHx1GSCizfcF019U",
        paseto.__encrypt(symmetric_key, "Love is stronger than hate or fear", "", nonce1))
    end)

    it("should pass 'Test Vector 2E-4-1'", function()
      assert.equal(
        "v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvbcqXgWxM3vJGrJ9kWqquP61Xl7bz4ZEqN5XwH7xyzV0QqPIo0k52q5sWxUQ4LMBFFso.Q3VvbiBBbHBpbnVz",
        paseto.__encrypt(null_key, "Love is stronger than hate or fear", "Cuon Alpinus", nonce2))
    end)

    it("should pass 'Test Vector 2E-4-2'", function()
      assert.equal(
        "v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvZMW3MgUMFplQXsxcNlg2RX8LzFxAqj4qa2FwgrUdH4vYAXtCFrlGiLnk-cHHOWSUSaw.Q3VvbiBBbHBpbnVz",
        paseto.__encrypt(full_key, "Love is stronger than hate or fear", "Cuon Alpinus", nonce2))
    end)

    it("should pass 'Test Vector 2E-4-3'", function()
      assert.equal(
        "v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvl05z9GIX0cnol6UK94cfV77AXnShlUcNgpDR12FrQiurS8jxBRmvoIKmeMWC5wY9Y6w.Q3VvbiBBbHBpbnVz",
        paseto.__encrypt(symmetric_key, "Love is stronger than hate or fear", "Cuon Alpinus", nonce2))
    end)

    it("should pass 'Test Vector 2E-5'", function()
      assert.equal(
        "v2.local.lClhzVOuseCWYep44qbA8rmXry66lUupyENijX37_I_z34EiOlfyuwqIIhOjF-e9m2J-Qs17Gs-BpjpLlh3zf-J37n7YGHqMBV6G5xD2aeIKpck6rhfwHpGF38L7ryYuzuUeqmPg8XozSfU4PuPp9o8.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz",
        paseto.__encrypt(symmetric_key, message3, "Paragon Initiative Enterprises", nonce2))
    end)

    it("should pass 'Test Vector 2E-6'", function()
      assert.equal(
        "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        paseto.__encrypt(symmetric_key, message1, footer2, nonce2))
    end)

  end)

  describe("sign test vectors", function()

    it("should pass 'Test Vector S-1'", function()
      assert.equal(
        "v2.public.xnHHprS7sEyjP5vWpOvHjAP2f0HER7SWfPuehZ8QIctJRPTrlZLtRCk9_iNdugsrqJoGaO4k9cDBq3TOXu24AA",
        paseto.sign(secret_key, ""))
    end)

    it("should pass 'Test Vector S-2'", function()
      assert.equal(
        "v2.public.Qf-w0RdU2SDGW_awMwbfC0Alf_nd3ibUdY3HigzU7tn_4MPMYIKAJk_J_yKYltxrGlxEdrWIqyfjW81njtRyDw.Q3VvbiBBbHBpbnVz",
        paseto.sign(secret_key, "", "Cuon Alpinus"))
    end)

    it("should pass 'Test Vector S-3'", function()
      assert.equal(
        "v2.public.RnJhbmsgRGVuaXMgcm9ja3NBeHgns4TLYAoyD1OPHww0qfxHdTdzkKcyaE4_fBF2WuY1JNRW_yI8qRhZmNTaO19zRhki6YWRaKKlCZNCNrQM",
        paseto.sign(secret_key, "Frank Denis rocks"))
    end)

    it("should pass 'Test Vector S-4'", function()
      assert.equal(
        "v2.public.RnJhbmsgRGVuaXMgcm9ja3qIOKf8zCok6-B5cmV3NmGJCD6y3J8fmbFY9KHau6-e9qUICrGlWX8zLo-EqzBFIT36WovQvbQZq4j6DcVfKCML",
        paseto.sign(secret_key, "Frank Denis rockz"))
    end)

    it("should pass 'Test Vector S-5'", function()
      assert.equal(
        "v2.public.RnJhbmsgRGVuaXMgcm9ja3O7MPuu90WKNyvBUUhAGFmi4PiPOr2bN2ytUSU-QWlj8eNefki2MubssfN1b8figynnY0WusRPwIQ-o0HSZOS0F.Q3VvbiBBbHBpbnVz",
        paseto.sign(secret_key, "Frank Denis rocks", "Cuon Alpinus"))
    end)

    it("should pass 'Test Vector S-6'", function()
      assert.equal(
        "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifSUGY_L1YtOvo1JeNVAWQkOBILGSjtkX_9-g2pVPad7_SAyejb6Q2TDOvfCOpWYH5DaFeLOwwpTnaTXeg8YbUwI",
        paseto.sign(secret_key, message3))
      assert.equal(
        "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifcMYjoUaEYXAtzTDwlcOlxdcZWIZp8qZga3jFS8JwdEjEvurZhs6AmTU3bRW5pB9fOQwm43rzmibZXcAkQ4AzQs.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz",
        paseto.sign(secret_key, message3, "Paragon Initiative Enterprises"))
    end)

    it("should pass 'Test Vector S-7'", function()
      assert.equal(
        "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        paseto.sign(secret_key, message1, footer2))
    end)

  end)

end)
