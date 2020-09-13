-- require("luacov.tick")
-- local opaddr, bytestr, opcode = dis:match('^(%S+) %- ([%x ]+) %- (.+)$')

-- t1 = os.clock()
local asm_db = dofile 'D:\\_dev\\lua\\disasm\\disasm_x86.lua'
-- print(os.clock()-t1)

local diss = getDissectCode()
local funcs = diss.getReferencedFunctions()


-- local begin_addr = '7FF6DD777416'

-- local addr = getAddress(begin_addr)

local file = io.open('D:\\_dev\\lua\\disasm\\disasm.asm' , 'w')
local tnative = 0
local function disasm_region(addr0, size, file)
    local addr = addr0
    local disasm = createDisassembler()
    for i=1,size do
        local t1 = os.clock()
        local dis = disasm.disassemble(addr)
        local disdata = disasm.getLastDisassembleData()
        tnative = tnative + (os.clock()-t1)
        
        local bytestbl, opcode = disdata.bytes, disdata.opcode
        -- file:write(dis, '\n')

        local bytestbl_alt = readBytes(addr, 16, true)
        local cp = asm_db.decodeCodePoint(bytestbl_alt, 1, targetIs64Bit() and 64 or 32)
        if cp then
            -- cp:get_args()
            if cp.size~=#bytestbl or #cp.syns>1 then
                file:write(dis, '\n')
                for _, s in ipairs(cp.syns) do
                    local cptext = cp:textify(s)
                    if cp.size~=#bytestbl then file:write('SZ ERROR ', cp.size, ' ', #bytestbl ,'\n') end
                    local s_bytes = bytes2str(bytestbl_alt, 1, cp.size)
                    file:write(s_bytes, ' - ', cptext, '\n')
                end
            end
        else
            file:write(dis, '\n')
            file:write('ERROR\n')
        end

        addr = addr + #bytestbl
        if addr>addr0+size then break end
    end
end

local function scan_thr(thr)
    local maxi = 5000
    local up = maxi<#funcs-1 and maxi or #funcs-1
    local t0 = os.clock()
    for i=20,up do
        if os.clock()-t0 >= 1 then 
            print('.')
            file:flush()
            t0 = os.clock()
        end
        local len = 0x400
        local size = (funcs[i+1]-funcs[i])>len and len or funcs[i+1]-funcs[i]
        local r = xpcall( disasm_region, function (err) print(err,debug.traceback()) end, funcs[i], size, file)
        if not r then
            break
        end
    end
    print('finished')
    file:close()
    print('tnative',tnative)
end

local thr = createThread(scan_thr)

-- disasm_region(0x7FF7C6E5687D, 0x400, file)
-- file:close()

-- assert(reg)
-- ProFi = dofile 'D:\\_dev\\lua\\disasm\\ProFi.lua'
-- ProFi:setInspect('decodeFullOp', 2)
-- ProFi:start()
-- local r = xpcall( decodeSolo, function (err) print(err,debug.traceback()) end, reg)
-- ProFi:stop()
-- ProFi:writeReport( 'D:\\_dev\\lua\\disasm\\MyProfilingReport.txt' )

-- file:close()