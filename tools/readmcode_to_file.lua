local diss = getDissectCode()
local funcs = diss.getReferencedFunctions()

local file = io.open('D:\\_dev\\lua\\disasm\\mcode64_fact.bin' , 'wb')


local sz1 = 0x2000
local sz2 = 100000
local topi = #funcs<=sz2 and #funcs or sz2
local t1 = os.clock()
for i=10,topi-1 do
    local size = (funcs[i+1]-funcs[i])>sz1 and sz1 or funcs[i+1]-funcs[i]
    local fmtstr = ('B'):rep(size)
    local reg = readBytes(funcs[i], size, true)
    if reg then
        file:write( string.pack(fmtstr,table.unpack(reg)) )
    end
    -- print(sz1, #reg, string.packsize(fmtstr))
end
local t = os.clock()-t1

file:close()
print(t)