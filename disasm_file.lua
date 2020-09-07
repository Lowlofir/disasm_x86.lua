-- local opaddr, bytestr, opcode = dis:match('^(%S+) %- ([%x ]+) %- (.+)$')

-- local ProFi = dofile 'D:\\_dev\\lua\\disasm\\ProFi.lua'
-- local profiler = require("profiler")

-- t1 = os.clock()
local asm_db = dofile 'D:\\_dev\\lua\\disasm\\asm.lua'
-- print(os.clock()-t1)

local disfile = io.open('D:\\_dev\\lua\\disasm\\disasm.asm' , 'w')

local function decodeSolo(bytes)
    local b_i = 1
    local size = #bytes
    while b_i < size-16 do
        local cp = asm_db.decodeCodePoint(bytes, b_i, 64)
        if cp then
            local cptext = cp:textify()
            if cp.debug then
                disfile:write(cp.debug, ':  ')
                local s_bytes = ''
                for i=1,cp.size do
                    s_bytes = s_bytes..('%02X'):format(bytes[i+b_i-1] or 0)..' '
                end
                disfile:write(('%06X'):format(b_i-1), ' - ', s_bytes, ' - ', cptext, '\n')
            end
            b_i = b_i + cp.size
        else
            disfile:write('ERROR\n')
            b_i = b_i + 1
        end
    end
end

local function decodeString(str)
    local bytes = setmetatable({ s = str }, {
        __index = function (t, i)
            return t.s:byte(i)
        end,
        __len = function (t)
            return #t.s
        end
    })
    return decodeSolo(bytes)
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
    return decodeSolo(metabytes)
end

-- ProFi:start()
local t1 = os.clock()
local file = io.open('D:\\_dev\\lua\\disasm\\mcode.bin' , 'rb')
local filedata_s = file:read('*all')
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
-- profiler.start()
t1 = os.clock()
-- decodeString(filedata_s)
for i=1,#filedata_arr do
    xpcall( decodeSolo, function (err) print(err..'\n',debug.traceback()) end, filedata_arr[i])
    -- xpcall( decodeBytesViaMt, function (err) print(err..'\n',debug.traceback()) end, filedata_arr[i])
    if os.clock()-t1 > 45 then
        print('break', i)
        break
    end
end
-- ProFi:stop()
-- profiler.stop()
print(os.clock()-t1)
-- ProFi:writeReport( 'D:\\_dev\\lua\\disasm\\MyProfilingReport.txt' )
-- profiler.report("profiler.log")
disfile:close()