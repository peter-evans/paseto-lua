local utils = {
  _VERSION     = 'paseto v0.1.0',
  _DESCRIPTION = 'PASETO (Platform-Agnostic Security Tokens) for Lua',
  _URL         = 'https://github.com/peter-evans/paseto-lua',
  _LICENSE     = [[
    MIT License

    Copyright (c) 2018 Peter Evans

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
  ]]
}

local ctable = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

function utils.tohex(str)
    return (str:gsub(".", function (c)
        return string.format("%02x", string.byte(c))
    end))
end

function utils.fromhex(str)
    return (str:gsub("..", function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

function utils.base64_encode(data, no_padding)
    return ((data:gsub(".", function(x)
        local r, ctab = "", x:byte()
        for i = 8, 1, -1 do
          r = r .. (ctab % 2 ^ i - ctab % 2 ^ (i - 1) > 0 and "1" or "0")
        end
        return r
    end) .. "0000"):gsub("%d%d%d?%d?%d?%d?", function(x)
        if (#x < 6) then
          return ""
        end
        local c = 0
        for i = 1, 6 do
          c = c + (x:sub(i, i) == "1" and 2 ^ (6 - i) or 0)
        end
        return ctable:sub(c + 1, c + 1)
    end) .. (no_padding and "" or ({ "", "==", "=" })[#data % 3 + 1]))
end

function utils.base64_decode(data)
    data = string.gsub(data, "[^" .. ctable .. "=]", "")
    return (data:gsub(".", function(x)
        if (x == "=") then
          return ""
        end
        local r, f = "", (ctable:find(x) - 1)
        for i = 6, 1, -1 do
          r = r .. (f % 2 ^ i - f % 2 ^ (i - 1) > 0 and "1" or "0")
        end
        return r
    end):gsub("%d%d%d?%d?%d?%d?%d?%d?", function(x)
        if (#x ~= 8) then
          return ""
        end
        local c = 0
        for i = 1, 8 do
          c = c + (x:sub(i, i) == "1" and 2 ^ (8 - i) or 0)
        end
        return string.char(c)
    end))
end

return utils
