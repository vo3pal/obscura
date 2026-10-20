"""Luau regressions for the source and VM pipelines."""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

from config import ObfuscationConfig, ProtectionLevel, lightweight_config
from obfuscator import Obfuscator

ROOT = Path(__file__).resolve().parents[1]
LUAU = Path(os.environ.get('LUAU_BIN', ROOT / 'tests/runtime/0.741' / ('luau.exe' if os.name == 'nt' else 'luau')))
if os.environ.get('OBSCURA_REQUIRE_RUNTIME') == '1' and not LUAU.is_file():
    raise RuntimeError('Set LUAU_BIN to the Luau executable.')


def run(source):
    code = 'game={GetService=function() return {} end}\nlocal function chunk(...)\n' + source + '''\nend
local values=table.pack(chunk(7,nil,9))
for i=1,values.n do
    local value=values[i]
    if type(value)=="string" then
        local bytes={}
        for j=1,#value do bytes[j]=tostring(string.byte(value,j)) end
        print("string:"..table.concat(bytes,","))
    else print(type(value)..":"..tostring(value)) end
end
print("count:"..values.n)
'''
    with tempfile.NamedTemporaryFile(mode='w', suffix='.luau', encoding='utf-8',
                                     delete=False, dir=ROOT / 'tests') as file:
        file.write(code)
        path = Path(file.name)
    try:
        result = subprocess.run([str(LUAU), '-O2', str(path)], capture_output=True,
                                text=True, timeout=5)
        if result.returncode:
            raise AssertionError(result.stderr)
        return result.stdout
    finally:
        path.unlink()


def configs(seed):
    yield lightweight_config(seed=seed)
    for level in ProtectionLevel:
        yield ObfuscationConfig(level=level, seed=seed)
    for profile in ('basic', 'client-max', 'max'):
        yield ObfuscationConfig(virtualize=True, vm_hardening=profile,
                               vm_predecode_bytecode=True, seed=seed)


@unittest.skipUnless(LUAU.is_file(), 'Set LUAU_BIN to run Luau tests.')
class LuauTests(unittest.TestCase):
    def compare(self, source):
        expected = run(source)
        for seed in (12345, 67890):
            for config in configs(seed):
                with self.subTest(seed=seed, level=config.level,
                                  profile=config.vm_hardening, cached=config.vm_predecode_bytecode):
                    self.assertEqual(run(Obfuscator(config).obfuscate(source)), expected)

    def test_assignments_and_tables(self):
        cases = [
            '''local t={10,20};local i=1;t[i],i=30,2;return t[1],t[2],i''',
            '''local t={10,20};local calls=0
local function key() calls+=1;return calls end
t[key()]+=5;return calls,t[1],t[2]''',
            '''local t={value=10};local old=t
local function rhs() t={value=100};return 5 end
t.value+=rhs();return old.value,t.value''',
            '''local t={20,"hello"};local calls=0
local function object() calls+=1;return t end
object()[1]-=2;object()[1]*=3;object()[1]/=2;object()[1]%=5;object()[1]^=3
object()[2]..=" world";return calls,t[1],t[2]''',
            '''local log="";local stored=10;local obj={}
setmetatable(obj,{__index=function() log..="g";return stored end,
__newindex=function(_,_,v) log..="s";stored=v end})
local function object() log..="o";return obj end
local function key() log..="k";return "value" end
local function rhs() log..="r";return 5 end
object()[key()]+=rhs();return log,stored''',
            '''local function values() return 7,nil,9 end
local t={1,2,x=3,values()};return t[1],t[2],t[3],t[4],t[5],t.x''',
            '''local function values() return 7,9 end
local t={values(),x=3};return #t,t[1],t[2],t.x''',
        ]
        for source in cases:
            self.compare(source)

    def test_returns_closures_and_loops(self):
        self.compare('''local function f(a,...) return a,select("#",...),... end
return f(1,nil,3,nil)''')
        self.compare('''local fs={};local total=0
for k,v in {3,7,11} do
if k==2 then continue end
fs[k]=function() return k,v end
for _,n in {2,5} do total+=v*n end
end
local k,v=fs[3]();return total,k,v''')
        self.compare('''local total=0;local i=0
repeat i+=1;if i%2==0 then continue end;total+=i until i>=6
local function factorial(n) if n<2 then return 1 end;return n*factorial(n-1) end
return total,factorial(7)''')
        modules = [
            ('return {Payload="..."}', 'assert(value.Payload=="...")'),
            ('''local m={Total=0};function m:Add(n) self.Total+=n;return self.Total end
return m''', 'assert(value:Add(5)==5 and value:Add(10)==15 and value.Total==15)'),
            ('local offset=7;return function(n) return n+offset end', 'assert(value(5)==12)'),
            ('return false', 'assert(value==false)'),
        ]
        for source, check in modules:
            for config in configs(12345):
                output = Obfuscator(config).obfuscate(source)
                harness = 'local function module(...)\n'+output+'\nend\n'
                harness += 'local values=table.pack(module());assert(values.n==1);local value=values[1]\n'
                self.assertEqual(run(harness+check+'\nreturn true'), 'boolean:true\ncount:1\n')

    def test_iterators_and_coroutines(self):
        self.compare('''local calls=0;local object=setmetatable({}, {
__iter=function(self) calls+=1
return function(_,previous)
local k=previous+1;if k<=3 then return k,k*7,k*11 end end,self,0 end,
__call=function() error("unexpected __call") end})
local total=0;for k,v,w in object do total+=v+w end;return total,calls''')
        self.compare('''local object=setmetatable({}, {__iter=function(self)
return function(_,previous)
local k=previous+1;if k<=2 then return k,coroutine.yield(k) end end,self,0 end})
local worker=coroutine.create(function()
local total=0;for k,v in object do total+=v end;return total end)
local a,b=coroutine.resume(worker);local c,d=coroutine.resume(worker,7)
local e,f=coroutine.resume(worker,11);return a,b,c,d,e,f,coroutine.status(worker)''')
        self.compare('''local events={};local object=setmetatable({}, {
__add=function(_,n) events[#events+1]=n;error("intentional") end})
local ok,problem=pcall(function() return object+13 end)
return ok,string.find(problem,"intentional",1,true)~=nil,table.concat(events,",")''')

    def test_strings_numbers_and_types(self):
        self.compare(r'return "a\nb\t\"c\\", "\000\2557", "\x41", "\u{1f600}",false,nil')
        self.compare('''export type Value = number | string
local text=[=[
type Price = 100
export type Name = example
]=];local value: number=15;return text,value''')
        self.compare('''local function f()
return 5050,0,-0.0,0.1,1.2345678901234567,9007199254740991,
1e308,1e-308,5e-324,false,nil,"inf","5050",1e309 end
local a=table.pack(f());a[a.n+1]=1/a[3];a.n+=1;return table.unpack(a,1,a.n)''')

    def test_payload_corruption(self):
        source='local function unused() return 9917 end;return 5050,"private-text",false,nil'
        output=Obfuscator(ObfuscationConfig(virtualize=True,vm_hardening='max',seed=12345)).obfuscate(source)
        self.assertEqual(run(output),run(source))
        fields=[r'bc=\{(\d+)', r'bk=\{q=\{(\d+)', r'ck=\{q=\{(\d+)',
                r'\},s=(\d+)', r'kc=(\d+)', r'np=(\d+)', r'ms=(\d+)', r'sp=\{(\d+)',
                r'bm=(\d+)', r'ba=(\d+)', r'om=(\d+)', r'oa=(\d+)', r'oi=(\d+)',
                r'ix=(\d+)', r'f1=(\d+)', r'f2=(\d+)', r'fq=(\d+)', r'fw=(\d+)',
                r'fb=(\d+)', r'ff=(\d+)', r'lm=(\d+)', r'la=(\d+)',
                r'xm=(\d+)', r'xa=(\d+)',
                r'fts=(\d+)', r'ftm=(\d+)', r'ft=\{(\d+)',
                r'ph=(\d+)', r'rh=(\d+)',
                r'pending=\{\[\d+\]=([12])',
                r'(?<!\w)k=\{[^}]*?\\(\d{3})']
        for pattern in fields:
            match=re.search(pattern,output)
            self.assertIsNotNone(match,pattern)
            value=int(match[1]);replacement=str((value+1)%256)
            if len(match[1])==3 and pattern==fields[-1]:
                replacement=f'{(value+1)%256:03d}'
            damaged=output[:match.start(1)]+replacement+output[match.end(1):]
            with self.subTest(field=pattern), self.assertRaisesRegex(AssertionError,'integrity check failed'):
                run(damaged)

    def test_large_native_closure(self):
        source=('local function factory()\n'
                +'\n'.join(f'local v{i}={i}' for i in range(190))
                +'\nlocal f=function() return {'+','.join(f'v{i}' for i in range(190))
                +','+','.join(f'"string{i}"' for i in range(20))+'} end\n'
                +';'.join(f'v{i}=v{i}+1' for i in range(190))
                +'\nreturn f end\nreturn #factory()()')
        self.assertEqual(run(Obfuscator(lightweight_config(seed=12345)).obfuscate(source)),run(source))
