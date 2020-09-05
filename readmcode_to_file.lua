local diss = getDissectCode()
local funcs = diss.getReferencedFunctions()

local file = io.open('D:\\_dev\\lua\\disasm\\mcode.bin' , 'wb')


local sz1 = 0x4000
local topi = #funcs<=10000 and #funcs or 10000
local t1 = os.clock()
for i=1000,topi do
    local size = (funcs[i+1]-funcs[i])>sz1 and sz1 or funcs[i+1]-funcs[i]
    local fmtstr = ('B'):rep(size)
    local reg = readBytes(funcs[i], size, true)
    file:write( string.pack(fmtstr,table.unpack(reg)) )
    -- print(sz1, #reg, string.packsize(fmtstr))
end
local t = os.clock()-t1

file:close()
print(t)