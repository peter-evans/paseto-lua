local paseto = require "paseto"

describe("paseto", function()

    describe("foo", function()

        it("returns the text 'Hello World!'", function()
          assert.equal(paseto.foo(), "Hello World!")
        end)

    end)

    describe("randombytes", function()

        it("Returns a string of n random bytes", function()
          assert.equal(string.len(paseto.randombytes(25)), 25)
        end)

    end)

end)
