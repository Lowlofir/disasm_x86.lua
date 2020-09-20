-- require("luacov")

-- local ProFi = dofile 'tools/ProFi.lua'

-- t1 = os.clock()
local asm = dofile 'disasm_x86.lua'
-- print(os.clock()-t1)

local disfile = io.open('disasm.asm' , 'w')


local function decodeDirect(bytes)
    local b_i = 1
    local size = #bytes
    while b_i <= size do

        local cp, err = asm.decodeCodePoint(bytes, b_i, 64)
        if cp then
            -- local cptext = cp:textify()
            -- if cp.debug then
                -- disfile:write(cp.debug, ':  ')
                local s_bytes = bytes2str(bytes, b_i, cp.size)
                -- disfile:write(('%06X'):format(b_i-1), ' - ', s_bytes, ' - ', cp:textify_full_reference(), '\n')
                -- disfile:write(('%06X'):format(b_i-1), ' - ', s_bytes, ' - ', cp:textify(), '\n')
                -- cp:get_args()
                -- end
            b_i = b_i + cp.size
        else
            if err=='no op match' then
                local s_bytes = bytes2str(bytes, b_i, 8)
                disfile:write(s_bytes, '\n')
            end
            disfile:write('ERROR '..(err or 'no err')..'\n')
            b_i = b_i + 1
        end
    end
end

local function decodeString(str)
    local bytes = setmetatable({}, {
        __index = function (t, i)
            return str:byte(i)
        end,
        __len = function (t)
            return #str
        end
    })
    return decodeDirect(bytes)
end

local function decodeBytesViaMt(bytes)
    local metabytes = setmetatable({ b = bytes }, {
        __index = function (t, i)
            return t.b[i]
        end,
        __len = function (t)
            return #t.b
        end
    })
    return decodeDirect(metabytes)
end

-- ProFi:start()
local t1 = os.clock()
local file = io.open('tools/mcode64_fact.bin' , 'rb')
local filedata_s = file:read('*all'):sub(1,2000000)
file:close()
print(os.clock()-t1)

local b_size = 1024*4
t1 = os.clock()
local filedata_arr = {}
for i=0,#filedata_s//b_size do
    filedata_arr[#filedata_arr+1] = {filedata_s:byte(i*b_size, (i+1)*b_size-1)}
end
local bytes_read = 0
for i=1,#filedata_arr do
    bytes_read = bytes_read + #filedata_arr[i]
end
print(os.clock()-t1)
-- print(#filedata_arr, bytes_read, #filedata_s)
assert(bytes_read==#filedata_s)
-- ProFi:stop()




-- ProFi:start()
t1 = os.clock()
xpcall( decodeString, function (err) print(err..'\n',debug.traceback()) end, filedata_s)
for i=1,#filedata_arr do
    -- xpcall( decodeDirect, function (err) print(err..'\n',debug.traceback()) end, filedata_arr[i])
    -- xpcall( decodeBytesViaMt, function (err) print(err..'\n',debug.traceback()) end, filedata_arr[i])
    if os.clock()-t1 > 20 then
        print('break', i)
        break
    end
end
-- ProFi:stop()
print(os.clock()-t1)
-- ProFi:writeReport( 'ProfilingReport.txt' )
disfile:close()