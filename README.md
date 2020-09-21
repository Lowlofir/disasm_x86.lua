# disasm_x86.lua

Library for simple analysis of x86(-64) instructions.

#### Supported instructions

Supports most of what included in x86reference xml file (general, system, x87 FPU, MMX, SSE, SSE1, SSE2, SSE3, SSSE3, SSE4, VMX, and SMX instructions). Definitely not supports what is not included in xml (e.g. AVX).

#### Status

Not ready for wide use. Anything can be changed at any time.

It decodes instructions fine, but output is not good enough for some applications. Please suggest improvements according to your use cases.

## How to

### Install

You need two files:
* `disasm_x86.lua` - from repository
* `disasm_x86_db.lua` - needs to be made by `asm_conv\make_db.py` (using `x86reference` files)

You can get them both like this:

1. Clone repository

```shell
git clone https://github.com/Lowlofir/disasm_x86.lua
cd disasm_x86.lua
git submodule update --init --recursive
```

2. Run `make_db.py`

```shell
python ./asm_conv/make_db.py
```

Now both `disasm_x86.lua` and `disasm_x86_db.lua` are in the cloned folder. Copy (or make symlinks to) them to any folder from Lua `package.path`, or add folder where this files already are to `package.path`, or whatever you like more.

### Use

```lua
local disasm = require 'disasm_x86'
```

Main function  is `decodeCodePoint` with parameters:

1. Array of bytes
2. Byte index in `bytes` to start decoding from (integer)
3. Architecture, should be 32 or 64 (integer)

Return values can be `nil, error_str` in case of error, or a table with data describing decoded binary instruction.

Currently the accepted input data format (first parameter) is array of bytes values, like:

```lua
local bytes = { 0x06, 0x37, 0x02, 0x00, 0x10, 0x37, 0x02, 0x00  }
```

The only operations performed with it are indexing (`bytes[i]`) and length (`#bytes`), so it is easy to make such a table (using metatable) that behaves compatible, and use it with strings or anything else.

Example:

```lua
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

local file = io.open('mcode64_1.bin' , 'rb')
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
```

Produces `dis.asm` file with text like:

```asm
000000 - PUSH rbx
000002 - SUB rsp,40
000006 - MOV [rsp+20],-2
00000F - MOV rbx,rcx
000012 - CMP [rcx+20],0
000017 - JZ/JE AE
00001D - MOV r9,[rdx]
000020 - MOV rax,r9
000023 - SHR rax,3
000027 - ADD rax,r9
00002A - MOV rdx,rax

.......

07D7CC - MOV eax,[rdx+rcx+14]
07D7D0 - MOV [rcx+14],eax
07D7D3 - MOV eax,[rdx+rcx+18]
07D7D7 - MOV [rcx+18],eax
07D7DA - MOV eax,[rdx+rcx+1C]
07D7DE - MOV [rcx+1C],eax
07D7E1 - MOV eax,[rdx+rcx+20]
07D7E5 - MOV [rcx+20],eax
07D7E8 - LEA rax,[rcx+30]
07D7EC - TEST rax,rax
07D7EF - JZ/JE 34
07D7F1 - MOVAPS XMM0,[rdx+rcx+30]
07D7F6 - MOVAPS [rax],XMM0
07D7F9 - MOVAPS XMM1,[rdx+rcx+40]
07D7FE - MOVAPS [rcx+40],XMM1
07D802 - MOV eax,[rdx+rcx+50]
07D806 - MOV [rcx+50],eax
07D809 - MOV eax,[rdx+rcx+54]
07D80D - MOV [rcx+54],eax
07D810 - MOV eax,[rdx+rcx+58]
07D814 - MOV [rcx+58],eax
07D817 - MOV eax,[rdx+rcx+5C]
07D81B - MOV [rcx+5C],eax
07D81E - MOV eax,[rdx+rcx+60]
07D822 - MOV [rcx+60],eax
07D825 - LEA rax,[rcx+70]
07D829 - TEST rax,rax

.......

```
