local module = {}

-- TODO: 6D insd, 

function table2str(t, lvl)
    lvl=lvl or 1
    local s = '{\n'
    for k,v in pairs(t) do
        if type(v)~='table' then
            s = s..(' '):rep(lvl*4)..tostring(k)..' : '..tostring(v)..'\n'
        else
            s = s..(' '):rep(lvl*4)..tostring(k)..' : '..table2str(v,lvl+1)..'\n'
        end        
    end
    return s..(' '):rep(lvl*4)..'},\n'
end

function to_shex(n, splus)
    if n>=0 then 
        return (splus and '+%X' or '%X'):format(n)
    else
        return ('-%X'):format(-n)
    end
end

local asm_db = dofile 'D:\\_dev\\lua\\disasm\\asm_conv\\asm_db.lua'

local asm_mnem_map = {}
local function create_mnem_map()
    for _,el in ipairs(asm_db.opcodes) do
        for syn_i, syn in ipairs(el.syns) do
            if not syn.mnem then goto continue end
            local t = { opcode = el, syn_i = syn_i }
            local lmnem = syn.mnem:lower()
            
            if not asm_mnem_map[lmnem] then
                asm_mnem_map[lmnem] = { [el] = {syn} }
            else
                asm_mnem_map[lmnem][el] = asm_mnem_map[lmnem][el] or {}
                table.insert(asm_mnem_map[lmnem][el], syn)
            end
            ::continue::
        end
    end
end

-- create_mnem_map = profiled(create_mnem_map, 'create_mnem_map')
-- create_mnem_map()

local asm_pref_map = {}
for _,el in ipairs(asm_db.prefixes) do
    asm_pref_map[el.opcd_pri] = el
end


local function makeLevel(flist)
    local masksmap = {}
    local ops = {}
    for _,f in ipairs(flist) do
        local mask = f[2]
        if mask then
            masksmap[mask] = masksmap[mask] or {}
            table.insert(masksmap[mask], f)
        else
            table.insert(ops, f.op)
        end
    end

    local level = { ops=ops }
    for mask, flist in pairs(masksmap) do
        local levelitem = { t='map', mask=mask, m = {} }
        local mm = {}
        for _,f in ipairs(flist) do
            local byte = f[1]
            mm[byte] = mm[byte] or {}
            assert(f.next)
            table.insert(mm[byte], f.next)
        end
        for byte,nxts in pairs(mm) do
            levelitem.m[byte] = makeLevel(nxts)
        end
        table.insert(level, levelitem)
    end
    return level
end

local function make_decoding_map()
    local bytemaplist = {}
    for _, op in ipairs(asm_db.opcodes) do
        local bt = {}
        if op.opcd_pref then
            bt[#bt+1] = {op.opcd_pref, ~0}
        end
        if op.opcd_sz==2 then
            bt[#bt+1] = {0x0F, ~0}
        end
        bt[#bt+1] = {op.opcd_pri, ~(op.opcd_bitfields or 0)}
        if op.opcd_sec then
            bt[#bt+1] = {op.opcd_sec, ~0}
        end
        if op.opcd_ext then
            bt[#bt+1] = {op.opcd_ext<<3, 7<<3}
        end
        bt[#bt+1] = { op=op }
        for i=1,#bt-1 do
            bt[i].next = bt[i+1]
        end
        table.insert(bytemaplist, bt)
    end
    local fsts = {}
    for _, bm in ipairs(bytemaplist) do
        table.insert(fsts, bm[1])
    end
    return makeLevel(fsts)
end

-- make_decoding_map = profiled(make_decoding_map, 'make_decoding_map')
local asm_decoding_map = make_decoding_map()
assert(asm_decoding_map)


local function tbl_is_in(t, o)
    for i=1,#t do
        if t[i]==o then
            return true
        end        
    end
    return false
end

local function match_to_opcode(op, bytes)
    local bi = 1
    if op.opcd_pref and bytes[bi]==op.opcd_pref then
        -- print('opcd_pref', op.opcd_pref)
        bi = bi + 1
    elseif op.opcd_pref then
        return false
    end
    if asm_pref_map[bytes[bi]] then  -- prefixes
        bi=bi+1
        if asm_pref_map[bytes[bi]] then  -- prefixes
            bi=bi+1
        end
    end
    if op.opcd_sz==2 and bytes[bi]==0x0F then
        bi = bi + 1
    elseif op.opcd_sz==2 then
        return false
    end
    if not op.opcd_pri or not bytes[bi] then
        for k,v in pairs(op) do
            print(k,tostring(v))
        end
        local s = ''
        for i,v in ipairs(bytes) do
            s=s..('%X'):format(v)..' '
        end
        print(s)
        print('bi=',bi)
        return false
        -- error('not bytes[bi]')
    end
    local bfmask = op.opcd_bitfields and ~op.opcd_bitfields or ~0
    if (bytes[bi] & bfmask)==op.opcd_pri then
        bi = bi + 1
    else
        return false
    end
    if op.opcd_ext and ((bytes[bi] & 7<<3) ~ (op.opcd_ext<<3))==0 then
        
    elseif op.opcd_ext then
        return false
    end
    return true
end


local function prints(st, ...)
    assert(type(st)=='table')
    local t = {}
    for i, v in ipairs({...}) do
        t[#t+1] = tostring(v)
    end
    st[#st+1] = table.concat(t, ' ')
end

local function opsEqualExceptPrefix(op1, op2)
    if  op1.opcd_pri == op2.opcd_pri and
        op1.opcd_sz == op2.opcd_sz and
        op1.opcd_ext == op2.opcd_ext and
        op1.opcd_sec == op2.opcd_sec 
    then
        return true
    else
        return false
    end
end

local function opsEqualExceptBitness(op1, op2)
    if  op1.opcd_pri == op2.opcd_pri and
        op1.opcd_sz == op2.opcd_sz and
        op1.opcd_ext == op2.opcd_ext and
        op1.opcd_sec == op2.opcd_sec and 
        op1.opcd_pref == op2.opcd_pref
    then
        return true
    else
        return false
    end
end


local function intermatch(op_recs, bitness)
    local new_recs = {}
    for _, op_rec in ipairs(op_recs) do
        local op = op_rec[1]
        if op.opcd_pref and asm_pref_map[op.opcd_pref] then
            for _,op_rec2 in ipairs(op_recs) do
                local op2 = op_rec2[1]
                if not opsEqualExceptPrefix(op, op2) or op.opcd_pref==op2.opcd_pref then
                    table.insert(new_recs, op_rec2)
                end
            end
            op_recs = new_recs
            break
        end
    end
    if not bitness then return op_recs end

    local bitp = 'only_'..tostring(bitness)
    local bit_dominator
    for _, op_rec in ipairs(op_recs) do
        local op = op_rec[1]
        if op[bitp] then
            bit_dominator = op
            break
        end
    end

    if bit_dominator then
        new_recs = {}
        for _, op_rec in ipairs(op_recs) do
            local op = op_rec[1]
            if not opsEqualExceptBitness(bit_dominator, op) or (bit_dominator[bitp] and op[bitp]) then
                table.insert(new_recs, op_rec)
            end
        end
        op_recs = new_recs
    end

    return op_recs
end
-- intermatch = profiled(intermatch, 'intermatch')


local function intermatch_nr(ops, bitness)
    local new_ops = {}
    for i=1,#ops do
        local op = ops[i]
        if op.opcd_pref and asm_pref_map[op.opcd_pref] then
            for i=1,#ops do
                local op2 = ops[i]
                if not opsEqualExceptPrefix(op, op2) or op.opcd_pref==op2.opcd_pref then
                    new_ops[#new_ops+1] = op2
                end
            end
            ops = new_ops
            break
        end
    end
    if not bitness then return ops end

    local bitp_my = 'only_'..tostring(bitness)
    local bitp_notmy = bitness==64 and 'only_32' or 'only_64'

    new_ops = {}
    for i=1,#ops do
        local op = ops[i]
        if not op[bitp_notmy] then
            new_ops[#new_ops+1] = op
        end
    end
    ops = new_ops

    if bitness==64 then
        local bit_dominator
        for i=1,#ops do
            local op = ops[i]
            if op[bitp_my] then
                bit_dominator = op
                break
            end
        end

        if bit_dominator then
            new_ops = {}
            for i=1,#ops do
                local op = ops[i]
                if not opsEqualExceptBitness(bit_dominator, op) or (bit_dominator[bitp_my] and op[bitp_my]) then
                    table.insert(new_ops, op)
                end
            end
            ops = new_ops
        end
    end
    
    if #ops==2 and ops[1].opcd_pri==0x90 and ops[1].opcd_sz==1 then  -- XCHG rax,rax is NOP
        if ops[1].syns[1].mnem == 'NOP' then
            return {ops[1]}
        else
            return {ops[2]}
        end
    end

    return ops
end

-- intermatch_nr = profiled(intermatch_nr, 'intermatch_nr')



local function calcOpSizes(rex, x66, x67, bitmode)
    local REXW = (rex&8)>0  -- boolean
    local opsize
    if REXW then opsize = 8
    elseif not x66 then opsize = 4
    else opsize = 2 end

    local addrsz = bitmode
    if x67 then addrsz=addrsz//2 end
    return opsize, addrsz
end

local function decodeModRM(op, modrm_val, rex, x67, bitmode)
    rex = rex or 0
    local b = modrm_val
    local rm = (b & 7) -- + ((rex&1)<<3)
    local reg = (b>>3 & 7) + ((rex&4)<<1)
    local mod = (b>>6 & 3)
    if op.opcd_ext then
        reg = rm + ((rex&1)<<3)
    end
    local disp   -- remains nil if mod==0b11
    if mod<=1 then disp=mod
    elseif mod==2 then disp=4 end

    if rm==4 and disp then  -- SIB
        return { sib = true, disp = disp, reg = reg }
    elseif rm==5 and mod==0 then  
        if bitmode==64 then
            return { disp = 4, reg = reg, rm = x67 and 'eip' or 'rip' }
        else
            return { disp = 4, reg = reg, rm = '0' }
        end
    end
    -- if not op.opcd_ext then
        rm = rm + ((rex&1)<<3)
    -- else
    --     rm = nil
    -- end
    return { disp = disp, reg = reg, rm = rm }
end

local function decodeSIB(sib_v, modrm_v, rex)
    rex = rex or 0
    local mod = (modrm_v>>6 & 3)
    local scale = 1 << (sib_v>>6 & 3)
    local index = (sib_v>>3 & 7) + ((rex&2)<<2)
    local base = (sib_v & 7) + ((rex&1)<<3)

    if index==4 then
        scale = 0
    end
    if mod==0 and sib_v&7==5 then
        base = nil  -- means disp32
    end
    return { scale = scale, index = index, base = base }
end

local function search_decoding_level(res, level, bytes, byte_i)
    for opi = 1,#level.ops do
        res[#res+1] =  level.ops[opi]
    end
    for _,lvlitem in ipairs(level) do
        -- assert(lvlitem.t=='map')
        local byte = bytes[byte_i]
        if not byte then   -- no more bytes
            return
        end
        local nextlevel = lvlitem.m[byte & lvlitem.mask]
        if nextlevel then
            search_decoding_level(res, nextlevel, bytes, byte_i+1)
        end
    end
end

local function search_decoding_level_1(level, byte)
    local nexts = {}
    for _,lvlitem in ipairs(level) do
        -- assert(lvlitem.t=='map')
        local nextlevel = lvlitem.m[byte & lvlitem.mask]
        if nextlevel then
            table.insert(nexts, nextlevel)
        end
    end
    return nexts
end

local function decode_prefixes(bytes, byte_i)
    local prefs = {}
    for i=1,16 do
        local b = bytes[byte_i]
        if not b then            -- no more bytes
            return prefs, byte_i 
        end  
        if b&0xF0 == 0x40 then
            prefs.rex = b
            byte_i = byte_i + 1
            goto cont
        end
        if asm_pref_map[b] then
            table.insert(prefs, b)
            byte_i = byte_i + 1
        else
            break
        end
        ::cont::
    end
    return prefs, byte_i
end

function module.decodeOp(bytes, byte_i, bitness)
    -- assert(asm_decoding_map)
    local prefs, byte_i = decode_prefixes(bytes, byte_i)
    local ops = {}
    if #prefs>0 then
        local lvls
        lvls = search_decoding_level_1(asm_decoding_map, prefs[1])
        for _,l in ipairs(lvls) do
            search_decoding_level(ops, l, bytes, byte_i)
        end
    end
    search_decoding_level(ops, asm_decoding_map, bytes, byte_i)

    -- local dbg = false

    ---  filter by mem/nomem
    local new_ops = {}
    for i=1,#ops do
        local op = ops[i]
        local bi = byte_i + op.opcd_sz
        if op.modrm and op.opcd_mod and bytes[bi] then
            local mod = (bytes[bi]>>6 & 3)
            if (mod == 3) == (op.opcd_mod == 'nomem') then
                new_ops[#new_ops+1] = op
            end
        else
            new_ops[#new_ops+1] = op
        end
    end
    ops = new_ops

    ops = intermatch_nr(ops, bitness)
    -- assert(#ops<=1)
    if #ops==0 then 
        return ops 
    end
    return ops, byte_i, prefs
end


local function decodeOpInitial(bytes, byte_i, bitness)
    local byte_i_0 = byte_i
    local ops, byte_i, prefs = module.decodeOp(bytes, byte_i, bitness)
    if #ops==0 then return end
    if #ops~=1 then
        local s=''
        for i=0, 7 do
            s=s..('%X'):format(bytes[byte_i_0+i])..' '
        end
        -- print(s)
        -- print(table2str(ops))
        return
    end
    local maxbi = #bytes

    -- assert(#ops==1)
    local op = ops[1]
    byte_i = byte_i + op.opcd_sz
    local Z = bytes[byte_i-1] & 7
    local modrm
    local sib 
    if op.modrm then
        if byte_i>maxbi then return end
        modrm = decodeModRM(op, bytes[byte_i], prefs.rex, tbl_is_in(prefs, 0x67), bitness)
        byte_i = byte_i + 1
        if modrm.sib then
            if byte_i>maxbi then return end
            sib = decodeSIB(bytes[byte_i], bytes[byte_i-1], prefs.rex)
            modrm.sib = sib
            byte_i = byte_i + 1
        end
        if sib and not sib.base then
            modrm.disp = 4
        end
    end
    return op, modrm, prefs, byte_i, Z
end

local function countImmsBytes(op, prefs, bitness)
    assert(op.imms)
    local byte_i = 0
    for _, imm in ipairs(op.imms) do
        local imm_sz = imm.s
        if imm.s == 'addr' then
            imm_sz = bitness//8
        else
            assert(type(imm.s)=='number')
            
            if (prefs.rex or 0)&8 ~= 0 then
                if imm.rexw == 'promote' then
                    imm_sz = 8
                elseif imm.rexw == 'ignore' then    
                    -- ignore
                elseif imm.rexw == 'uimpl' then
                    op.debug = true
                end
            end
            if imm.x66 and tbl_is_in(prefs, 0x66) then
                if imm.x66=='uimpl' then 
                    op.debug = true
                else
                    imm_sz = imm.x66
                end
            end
        end
        byte_i = byte_i + imm_sz
    end
    return byte_i
end

function module.decodeFullOp(bytes, byte_i, bitness)
    local byte_i_0 = byte_i
    local op, modrm, prefs, byte_i = decodeOpInitial(bytes, byte_i, bitness)
    if modrm.disp then
        byte_i = byte_i + modrm.disp
    end
    if op.imms then
        for _, imm in ipairs(op.imms) do
            local imm_sz = imm.s
            if imm.s == 'addr' then
                imm_sz = bitness//8
            else
                assert(type(imm.s)=='number')
                
                if (prefs.rex or 0)&8 ~= 0 then
                    if imm.rexw == 'promote' then
                        imm_sz = 8
                    elseif imm.rexw == 'ignore' then    
                        -- ignore
                    elseif imm.rexw == 'uimpl' then
                        op.debug = true
                    end
                end
                if imm.x66 and tbl_is_in(prefs, 0x66) then
                    if imm.x66=='uimpl' then 
                        op.debug = true
                    else
                        imm_sz = imm.x66
                    end
                end
            end
            byte_i = byte_i + imm_sz
        end
    end
    return op, modrm, byte_i-byte_i_0
end
-- module.decodeFullOp = profiled(module.decodeFullOp, 'decodeFullOp')

local function readToNumber(bytes, byte_i, b_n)
    local value = 0
    local v_b_i = b_n - 1
    repeat
        value = value<<8
        value = value + bytes[byte_i+v_b_i]
        v_b_i = v_b_i - 1
    until v_b_i<0
    return value - (value&1<<(b_n*8-1))*2
end

local function readImm(imm, bytes, byte_i, prefs, bitness)
    local imm_sz = imm.s
    if imm.s == 'addr' then
        imm_sz = bitness//8
    else
        assert(type(imm.s)=='number')
        
        if (prefs.rex or 0)&8 ~= 0 then
            if imm.rexw == 'promote' then
                imm_sz = 8
            elseif imm.rexw == 'ignore' then    
                -- ignore
            elseif imm.rexw == 'uimpl' then
                -- op.debug = true
            end
        end
        if imm.x66 and tbl_is_in(prefs, 0x66) then
            if imm.x66=='uimpl' then 
                -- op.debug = true
            else
                imm_sz = imm.x66
            end
        end
    end
    return readToNumber(bytes, byte_i, imm_sz), imm_sz
end

local asm_regs = { 'ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di' }
local asm_regs2 = { 'a', 'c', 'd', 'b', 'sp', 'bp', 'si', 'di' }

local asm_regs_seg = { 'ES', 'CS', 'SS', 'DS', 'FS', 'GS' }
local asm_regs_grps = { x87fpu='ST', mmx='MMX', xmm='XMM', ctrl='CR', debug='DR' }


local code_point_mt = {}
code_point_mt.__index = code_point_mt

local function textifyGenRegister(reg_i, reg_sz, rex) -- reg_i from 0, reg_sz from 1 to 8, rex is bool-tested
    if reg_i<8 then
        if reg_sz>=2 then
            local prefix = reg_sz<4 and '' or (reg_sz==4 and 'e' or 'r')
            return prefix..asm_regs[reg_i+1]
        else
            local reg_lh = 'l'
            if not rex then 
                reg_i = reg_i%4 
                reg_lh = reg_i//4>0 and 'h' or 'l'
            end
            return asm_regs2[reg_i+1]..reg_lh
        end
    else   
        local pfix = reg_sz>4 and '' or (reg_sz==4 and 'd' or (reg_sz==2 and 'w' or 'l'))
        return 'r'..tostring(reg_i)..pfix
    end
end

local function textifyRegister(reg_i, reg_sz, rex, reg_group) -- reg_i from 0, reg_sz from 1 to 8, rex is bool-tested
    assert(reg_i)
    assert(reg_sz)
    assert(type(reg_group) == 'string')
    if reg_group=='gen' then return textifyGenRegister(reg_i, reg_sz, rex) 
    elseif reg_group=='seg' then
        return asm_regs_seg[reg_i%8+1]
    elseif asm_regs_grps[reg_group] then
        return asm_regs_grps[reg_group]..tostring(reg_i)
    else
        print('textifyRegister2 out of groups on ', tostring(reg_i), tostring(reg_sz), tostring(rex), tostring(reg_group))
    end
end


function code_point_mt:textify(syn_i)
    local syn = self.syns[syn_i or 1]
    local op = self.op
    local opname = type(syn.mnem)=='table' and table.concat(syn.mnem, '/') or syn.mnem
    local args = {}
    if op.modrm then
        local rm_reg
        if type(self.modrm.rm)=='string' then 
            rm_reg = self.modrm.rm
        elseif self.modrm.rm then
            rm_reg = textifyGenRegister(self.modrm.rm, self._op_sz_attr, self.prefs.rex)
        end
        if rm_reg and (self.modrm.disp or 0)>0 then
            rm_reg = '['..rm_reg..(self._disp_value>0 and '+' or '')..tostring(self._disp_value)..']'
        elseif rm_reg and self.modrm.disp==0 then
            rm_reg = '['..rm_reg..']'
        end

        local reg_reg = textifyGenRegister(self.modrm.reg, self._op_sz_attr, self.prefs.rex)
        

        if op.bit_dir==0 then
            args[#args+1] = rm_reg
            args[#args+1] = reg_reg
        elseif op.bit_dir==1 then
            args[#args+1] = reg_reg
            args[#args+1] = rm_reg
        else
            args[#args+1] = reg_reg
        end
    end
    if self._imm_values then
        for _,immv in ipairs(self._imm_values) do
            args[#args+1] = to_shex(immv)
        end
    end
    return opname..' '..table.concat(args, ',')
end

-- (gen|mmx|xmm|seg|x87fpu|ctrl|systabp|msr|debug|xcr)
local asm_addr_reg = { C='ctrl', D='debug', G='gen', P='mmx', S='seg', V='xmm' } --  T='test'
local asm_addr_rm = { E={'gen','mem'}, ES={'x87fpu','mem'}, EST={'x87fpu'}, H={'gen'}, M={'mem'}, N={'mmx'},
                      Q={'mmx','mem'}, R={'gen'}, U={'xmm'}, W={'xmm','mem'} }

local asm_addr_imm = { I=true, J=true, O=true }
-- special: H, Z, O?

function code_point_mt:textify2(syn)
    local syn = syn or self.syns[1]
    local op = self.op
    local opname = type(syn.mnem)=='table' and table.concat(syn.mnem, '/') or syn.mnem
    
    local args = {}
    local i = 0
    local imm_i = 1
    for _, p in ipairs(syn.params) do
        if p.hidden then goto continue end

        if not p.address then
            assert(p.value)
            if p.nr then
                args[#args+1] = textifyRegister(tonumber(p.nr), self._op_sz_attr, self.prefs.rex, p.group)
            else
                args[#args+1] = p.value
            end
            i=i+1
            goto continue
        end

        if p.address=='Z' then
            local reg = self._Z
            args[#args+1] = textifyGenRegister(reg, self._op_sz_attr, self.prefs.rex)
            goto continue
        end


        local reg_lp = asm_addr_reg[p.address]
        if reg_lp then
            assert(self.modrm)
            args[#args+1] = textifyRegister(self.modrm.reg, self._op_sz_attr, self.prefs.rex, reg_lp)
            goto continue
        end
        local rm_lp = asm_addr_rm[p.address]
        if rm_lp then
            assert(self.modrm)
            if (self.modrm.disp and not tbl_is_in(rm_lp, 'mem')) or (not self.modrm.disp and p.address=='M') then
                return opname..': INVALID SYNTAX'
            end
            if self.modrm.disp then  -- mod != 11
                local a
                if not self.modrm.sib then  -- no SIB
                    local disp_str = self._disp_value and to_shex(self._disp_value, true) or ''
                    if self.modrm.rm=='0' then
                        a = ('[%s]'):format(disp_str)
                    elseif type(self.modrm.rm)=='string' then
                        a = ('[%s%s]'):format(self.modrm.rm, disp_str)
                    else
                        local rs = textifyRegister(self.modrm.rm, self._op_sz_attr, self.prefs.rex, rm_lp[1]~='mem' and rm_lp[1] or 'gen')
                        a = ('[%s%s]'):format(rs, disp_str)
                    end
                else  -- SIB
                    a = '[SIB]'
                end
                assert(a)
                args[#args+1] = a
                goto continue
            else                   -- mod == 11
                args[#args+1] = textifyRegister(self.modrm.rm or self._Z, self._op_sz_attr, self.prefs.rex, rm_lp[1]~='mem' and rm_lp[1] or 'gen')
                goto continue
            end
        end
        if asm_addr_imm[p.address] then
            if p.value then goto continue end
            local a
            local val = self._imm_values[imm_i]
            imm_i=imm_i+1
            if p.address=='I' then
                a = to_shex(val)
            elseif p.address=='J' then
                a = to_shex(val, true)
            elseif p.address=='O' then
                assert(not self.modrm)
                a = ('[%X]'):format(val)
            end
            args[#args+1] = a
            goto continue
        end
        print('############', p.address)

        ::continue::
    end

    return opname..' '..table.concat(args, ',')
end


local function decodeCodePoint(bytes, byte_i, bitness)
    local byte_i_0 = byte_i
    local op, modrm, prefs, byte_i, Z = decodeOpInitial(bytes, byte_i, bitness)
    if not op then return end
    local disp_value
    if modrm and modrm.disp and modrm.disp>0 then
        disp_value = readToNumber(bytes, byte_i, modrm.disp)
        byte_i = byte_i + modrm.disp
    end
    local imm_values
    if op.imms then
        imm_values = {}
        for i=1,#op.imms do
            local sz
            imm_values[i], sz = readImm(op.imms[i], bytes, byte_i, prefs, bitness)
            byte_i = byte_i + sz
        end
    end

    local rexw = (prefs.rex or 0)&8 ~= 0

    local code_point = setmetatable({}, code_point_mt)
    code_point.prefs = prefs
    code_point.op = op
    code_point.modrm = modrm
    code_point.size = byte_i - byte_i_0 
    code_point._disp_value = disp_value
    code_point._imm_values = imm_values
    code_point._Z = Z

    local mod
    if modrm then
        mod = (modrm.disp == nil) and 'nomem' or 'mem'
    end
    local op_sz_attr = rexw and 8 or 4
    if tbl_is_in(prefs, 0x66) then op_sz_attr=2 end
    code_point._op_sz_attr = op_sz_attr

    local syntaxes = {}
    for i,s in ipairs(op.syns) do
        if ((s.op_szs and tbl_is_in(s.op_szs, op_sz_attr)) or not s.op_szs) and (not s.mod or s.mod == mod) then
            syntaxes[#syntaxes+1] = s
        end
    end
    code_point.syns = syntaxes
    assert(#syntaxes>0)

    return code_point
end

module.decodeCodePoint = decodeCodePoint


function module.find(opname, bytearr, bitness)
    local st = {}
    if opname=='ret' then opname = 'retn' end
    if opname=='int 3' then opname = 'int' end

    local op_recs = asm_mnem_map[opname]
    if not op_recs then prints(st, 'not op_recs') return end

    local ops_r2 = {}
    local ops_n = 0
    for op, syns in pairs(op_recs) do
        if match_to_opcode(op, bytearr) then
            ops_r2[#ops_r2+1] = {op, syns}
        end
        ops_n=ops_n+1
    end
    if #ops_r2>1 and opname~='nop' then
        prints(st, ops_n)
        prints(st, 'F:',#ops_r2)
        ops_r2 = intermatch(ops_r2, bitness)
        prints(st, 'FF:',#ops_r2)
    end

    return ops_r2, table.concat(st, '\n')..'\n'
end


return module