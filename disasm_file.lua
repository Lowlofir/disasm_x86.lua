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
        local dec, modrm, dec_sz = asm_db.decodeFullOp(bytes, b_i, 64)
        if dec then
            -- disfile:write(('%06X'):format(b_i-1), ' - ', dec.syns[1].mnem, '\n')
            disfile:write(('%06X'):format(b_i-1), ' - ', '\n')
            b_i = b_i + dec_sz
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
for i=1,#filedata_arr do
    xpcall( decodeSolo, function (err) print(err,debug.traceback()) end, filedata_arr[i])
    if os.clock()-t1 > 20 then
        print('break')
        break
    end
end
-- ProFi:stop()
print(os.clock()-t1)
ProFi:writeReport( 'D:\\_dev\\lua\\disasm\\MyProfilingReport.txt' )

disfile:close()