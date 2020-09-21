local disasm = require 'disasm_x86'


local function adapt_string(str)
    local byteslike = setmetatable({}, {
        __index = function (t, i)
            return str:byte(i)
        end,
        __len = function (t)
            return #str
        end
    })
    return byteslike
end

local file = io.open('tools\\mcode64_1.bin' , 'rb')
local filedata_s = file:read('*a')
file:close()

local bytes = adapt_string(filedata_s)
local disfile = io.open('dis.asm' , 'w')

local b_i = 1
while b_i <= #bytes do
    local cp, err = disasm.decodeCodePoint(bytes, b_i, 64)
    if cp then
        disfile:write(('%06X'):format(b_i-1), ' - ', cp:textify(), '\n')
        b_i = b_i + cp.size -- shift to after end of current instruction
    else
        disfile:write('ERROR '..(err or 'no err')..'\n')
        b_i = b_i + 1  -- maybe valid instruction starts on next byte?
    end
end

disfile:close()