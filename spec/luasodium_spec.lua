local luasodium = require "luasodium"

describe("luasodium", function()

  describe("luasodium constants", function()

    it("should get the version of luasodium", function()
      assert.equal("luasodium-", string.sub(luasodium.VERSION, 1, 10))
    end)

    it("should get the property SYMMETRIC_KEYBYTES", function()
      assert.equal(32, luasodium.SYMMETRIC_KEYBYTES)
    end)

    it("should get the property SYMMETRIC_NONCEBYTES", function()
      assert.equal(24, luasodium.SYMMETRIC_NONCEBYTES)
    end)

    it("should get the property SIGN_PUBLICKEYBYTES", function()
      assert.equal(32, luasodium.SIGN_PUBLICKEYBYTES)
    end)

    it("should get the property SIGN_SECRETKEYBYTES", function()
      assert.equal(64, luasodium.SIGN_SECRETKEYBYTES)
    end)

    it("should get the property SIGN_BYTES", function()
      assert.equal(64, luasodium.SIGN_BYTES)
    end)

  end)

  describe("sodium_version", function()

    it("should return the version of libsodium", function()
      assert.equal("string", type(luasodium.sodium_version()))
    end)

  end)

  describe("randombytes", function()

    it("should generate the minimum number of random bytes", function()
      assert.equal(0, #luasodium.randombytes(0))
    end)

    it("should generate the maximum number of random bytes", function()
      assert.equal(256, #luasodium.randombytes(256))
    end)

    it("should raise error 'Invalid number of bytes'", function()
      local bytes, err = luasodium.randombytes(257)
      assert.equal(nil, bytes)
      assert.equal("Invalid number of bytes", err)
    end)

  end)

  describe("sign_keypair", function()

    it("should generate a key pair", function()
      local secret_key, public_key = luasodium.sign_keypair()
      assert.equal(luasodium.SIGN_PUBLICKEYBYTES, #public_key)
      assert.equal(luasodium.SIGN_SECRETKEYBYTES, #secret_key)
      assert.equal(public_key, string.sub(secret_key, 33, 64))
    end)

  end)

  describe("generic hash", function()

    it("should create a generic hash", function()
      local hash = luasodium.generichash("test", "key", 24)
      assert.equal(24, #hash)
    end)

    it("should raise error 'Invalid hash size'", function()
      local hash, err = luasodium.generichash("test", "key", 15)
      assert.equal(nil, hash)
      assert.equal("Invalid hash size", err)
    end)

  end)

  describe("aead encrypt/decrypt", function()

    local nonce, key

    setup(function()
      nonce = luasodium.randombytes(24)
      key = luasodium.randombytes(32)
    end)

    it("should encrypt and decrypt", function()
      local ciphertext = luasodium.aead_encrypt("test", "123abc", nonce, key)
      local decrypted = luasodium.aead_decrypt(ciphertext, "123abc", nonce, key)
      assert.equal("test", decrypted)
    end)

    it("should raise error 'Invalid nonce size'", function()
      local ciphertext, err = luasodium.aead_encrypt("test", "123abc", "\0", key)
      assert.equal(nil, ciphertext)
      assert.equal("Invalid nonce size", err)
    end)

    it("should raise error 'Invalid key size'", function()
      local ciphertext, err = luasodium.aead_encrypt("test", "123abc", nonce, "\0")
      assert.equal(nil, ciphertext)
      assert.equal("Invalid key size", err)
    end)

    it("should raise error 'Message forged'", function()
      local ciphertext = luasodium.aead_encrypt("test", "123abc", nonce, key)
      local decrypted, err = luasodium.aead_decrypt(ciphertext, "789xyz", nonce, key)
      assert.equal(nil, decrypted)
      assert.equal("Message forged", err)
    end)

  end)

  describe("signing", function()

    local public_key, secret_key

    setup(function()
      secret_key, public_key = luasodium.sign_keypair()
    end)

    it("should sign and verify", function()
      local signature = luasodium.sign_detached("test", secret_key)
      local verified = luasodium.sign_verify_detached("test", signature, public_key)
      assert.equal("test", verified)
    end)

    it("should raise error 'Invalid secret key size'", function()
      local signature, err = luasodium.sign_detached("test", "\0")
      assert.equal(nil, signature)
      assert.equal("Invalid secret key size", err)
    end)

    it("should raise error 'Invalid public key size'", function()
      local signature = luasodium.sign_detached("test", secret_key)
      local verified, err = luasodium.sign_verify_detached("test", signature, "\0")
      assert.equal(nil, verified)
      assert.equal("Invalid public key size", err)
    end)

    it("should raise error 'Invalid signature for this message'", function()
      local verified, err = luasodium.sign_verify_detached("test", "\0", public_key)
      assert.equal(nil, verified)
      assert.equal("Invalid signature for this message", err)
    end)

  end)

end)
