local mymodule = require "mymodule"

describe("mymodule", function()

    describe("foo", function()

        it("returns the text 'Hello World!'", function()
          assert.equal(mymodule.foo(), "Hello World!")
        end)

    end)

end)