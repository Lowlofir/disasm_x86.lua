-- local opaddr, bytestr, opcode = dis:match('^(%S+) %- ([%x ]+) %- (.+)$')

local ProFi = dofile 'D:\\_dev\\lua\\disasm\\ProFi.lua'

-- t1 = os.clock()
local asm_db = dofile 'D:\\_dev\\lua\\disasm\\asm.lua'
-- print(os.clock()-t1)

local disfile = io.open('D:\\_dev\\lua\\disasm\\disasm.asm' , 'w')

local function decodeSolo(bytes)
    local b_i = 1
    local size = #bytes
    while b_i < size do
        local cp = asm_db.decodeCodePoint(bytes, b_i, 64)
        if cp then
            local s_bytes = ''
            for i=1,cp.size do
                s_bytes = s_bytes..('%02X'):format(bytes[i+b_i-1] or 0)..' '
            end
            disfile:write(('%06X'):format(b_i-1), ' - ', s_bytes, ' - ', cp:textify2(), '\n')
            b_i = b_i + cp.size
        else
            disfile:write('ERROR\n')
            b_i = b_i + 1
        end
    end
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


-- assert(reg)
-- ProFi:start()
t1 = os.clock()
-- for i=1,#filedata_arr do
for i=1,1 do
    xpcall( decodeSolo, function (err) print(err..'\n',debug.traceback()) end, filedata_arr[i])
    if os.clock()-t1 > 10 then
        print('break')
        break
    end
end
-- ProFi:stop()
print(os.clock()-t1)
-- ProFi:writeReport( 'D:\\_dev\\lua\\disasm\\MyProfilingReport.txt' )

disfile:close()