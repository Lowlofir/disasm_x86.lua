-- local opaddr, bytestr, opcode = dis:match('^(%S+) %- ([%x ]+) %- (.+)$')

-- t1 = os.clock()
local asm_db = dofile 'D:\\_dev\\lua\\disasm\\asm.lua'
-- print(os.clock()-t1)

local diss = getDissectCode()
local funcs = diss.getReferencedFunctions()


local begin_addr = '7FF6DD777416'

local addr = getAddress(begin_addr)

local file = io.open('D:\\Users\\Anon\\Documents\\My Cheat Tables\\disasm.asm' , 'w')
local tnative = 0
local function disasm_region(addr0, size, file)
    local addr = addr0
    -- file:write(('%X'):format(addr), '\n')
    local disasm = createDisassembler()
    for i=1,size do
        local t1 = os.clock()
        local dis = disasm.disassemble(addr)
        local disdata = disasm.getLastDisassembleData()
        tnative = tnative + (os.clock()-t1)
        
        local bytestbl, opcode = disdata.bytes, disdata.opcode
        local ops, dbgstr = asm_db.find(opcode, bytestbl, 64)
        
        local dec, modrm, dec_sz = asm_db.decodeFullOp(bytestbl, 1, 64)
        
        if (dbgstr and dbgstr~='\n') and (not ops or #ops~=1 or #ops[1][2]~=1) then
            file:write(dis, '\n')
            file:write(dbgstr or '')
        end

        -- if #dec~=1 then
        if dec_sz~=#bytestbl or (dec and dec.debug) then 
            if dec and dec.debug then
                file:write('dec.debug', '\n')
                dec.debug = false
            end
            file:write(dis, '\n')
        -- file:write(dbgstr or '')
            if not dec then
                file:write('INVALID', '\n')
            else
                file:write('SZ: ', dec_sz, '\n')
                file:write(table2str(dec), '\n')
                if modrm then
                    file:write(table2str(modrm), '\n')
                end
            end
        end
        -- end   
        
        addr = addr + #bytestbl
        if addr>addr0+size then break end
    end
end

local function scan_thr(thr)
    local t0 = os.clock()
    for i=1000,2000 do
        if os.clock()-t0 >= 1 then 
            print('.')
            t0 = os.clock()
        end
        local len = 0x1000
        local size = (funcs[i+1]-funcs[i])>len and len or funcs[i+1]-funcs[i]
        local r = xpcall( disasm_region, function (err) print(err,debug.traceback()) end, funcs[i], size, file)
        if not r then
            break
        end
    end
    print('finished')
    file:close()
    print('tnative',tnative)
    print_profiling()
end

-- local thr = createThread(scan_thr)

local reg = readBytes(funcs[1000], 0x40000, true)

local function decodeSolo(bytes)
    local b_i = 1
    local size = #reg
    while b_i < size do
        local dec, modrm, dec_sz = asm_db.decodeFullOp(bytes, b_i, 64)
        if dec then
            file:write(('%X'):format(b_i+addr-1), ' - ', dec.syns[1].mnem, '\n')
            b_i = b_i + dec_sz
        else
            file:write('ERROR\n')
            b_i = b_i + 1
        end
    end
end

-- assert(reg)
ProFi = dofile 'D:\\_dev\\lua\\disasm\\ProFi.lua'
-- ProFi:setInspect('decodeFullOp', 2)
ProFi:start()
local r = xpcall( decodeSolo, function (err) print(err,debug.traceback()) end, reg)
ProFi:stop()
ProFi:writeReport( 'D:\\_dev\\lua\\disasm\\MyProfilingReport.txt' )

file:close()