local paseto = require "paseto"

describe("paseto", function()

    describe("foo", function()

        it("returns the text 'Hello World!'", function()
          assert.equal(paseto.foo(), "Hello World!")
        end)

    end)

end)