


do
  local function runbenchmark(name, code, count, ob)
    local f = load([[
        local count,ob = ...
        local clock = os.clock
        local start = clock()
        for i=1,count do ]] .. code .. [[ end
        return clock() - start
    ]])
    print(f(count, ob).."\t"..name)
  end

  local nameof = {}
  local codeof = {}
  local tests  = {}
  function addbenchmark(name, code, ob)
    nameof[ob] = name
    codeof[ob] = code
    tests[#tests+1] = ob
  end
  function runbenchmarks(count)
    for _,ob in ipairs(tests) do
      runbenchmark(nameof[ob], codeof[ob], count, ob)
    end
  end
  function clearbenchmarks()
    nameof = {}
    codeof = {}
    tests = {}
  end
end
clearbenchmarks()
function makeob1()
  local self = {data = 0}
  function self:test()  self.data = self.data + 1  end
  return self
end
addbenchmark("Standard (solid)", "ob:test()", makeob1())

local ob2mt = {}
ob2mt.__index = ob2mt
function ob2mt:test()  self.data = self.data + 1  end
function makeob2()
  return setmetatable({data = 0}, ob2mt)
end
addbenchmark("Standard (metatable)", "ob:test()", makeob2())

function makeob3()
  local self = {data = 0};
  function self.test()  self.data = self.data + 1 end
  return self
end
addbenchmark("Object using closures (PiL 16.4)", "ob.test()", makeob3())

function makeob4()
  local public = {}
  local data = 0
  function public.test()  data = data + 1 end
  function public.getdata()  return data end
  function public.setdata(d)  data = d end
  return public
end
addbenchmark("Object using closures (noself)", "ob.test()", makeob4())

addbenchmark("Direct Access", "ob.data = ob.data + 1", makeob1())

addbenchmark("Local Variable", "ob = ob + 1", 0)
ab = 0
addbenchmark("Global Variable", "ab = ab + 1", {})
function func35()
end
addbenchmark("global func35 as ob", "ob()", func35)

addbenchmark("global func35", "func35()", {})

addbenchmark("empty", "", {})


runbenchmarks(100000000)
