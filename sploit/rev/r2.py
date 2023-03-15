from sploit.arch import arch
from sploit.log import ilog
from sploit.rev.gadget import Gadget
from sploit.symtbl import Symtbl
from sploit.util import run_cmd_cached

from collections import namedtuple as nt
from functools import cache
import json
import re

def run_cmd(binary,cmd):
    return run_cmd_cached(['r2','-q','-c',cmd,'-e','scr.color=false','-e','rop.len=10',binary])

def get_elf_symbols(elf):
    ilog(f'Retrieving symbols of {elf} with r2...')
    out = {}

    cmd_base = 'iI~baddr'
    base = run_cmd(elf,cmd_base)
    base = re.split(r'\s+',base[0])[1]
    base = int(base,0)

    cmd_syms = 'is'
    out_syms = run_cmd(elf,cmd_syms)
    out_syms = [re.split(r'\s+',sym) for sym in out_syms][4:]
    out_syms = [sym for sym in out_syms if sym[6].find('.')<0]
    out_syms = [sym for sym in out_syms if sym[4]=='FUNC' or sym[4]=='LOOS' or sym[4]=='TLS']
    out_syms = {sym[6]:int(sym[2],0) for sym in out_syms}
    out.update(out_syms)

    cmd_syms = 'ii~ FUNC '
    out_syms = run_cmd(elf,cmd_syms)
    out_syms = [re.split(r'\s+',sym) for sym in out_syms]
    out_syms = {"_PLT_"+sym[4]:int(sym[1],0) for sym in out_syms}
    out.update(out_syms)

    cmd_syms = 'fs relocs;f'
    out_syms = run_cmd(elf,cmd_syms)
    out_syms = [re.split(r'\s+',sym) for sym in out_syms]
    out_syms = {"_GOT_"+sym[2][sym[2].rfind('.')+1:]:int(sym[0],0) for sym in out_syms}
    out.update(out_syms)

    cmd_strs = 'fs strings;f'
    out_strs = run_cmd(elf,cmd_strs)
    out_strs = [re.split(r'\s+',sym) for sym in out_strs]
    out_strs = {sym[2][sym[2].rfind('.')+1:]:int(sym[0],0) for sym in out_strs}
    out.update(out_strs)

    return Symtbl(base=base, **out)

def get_locals(binary,func):
    ilog(f'Retrieving local stack frame of {hex(func)} in {binary} with r2...')

    addr = hex(func)
    cmd_locals = f's {func};af;aafr;aaft;afvf'
    out = run_cmd(binary,cmd_locals)
    out = [re.split(r':?\s+',var) for var in out]
    out = {var[1]:-(int(var[0],0)-arch.wordsize) for var in out}
    return Symtbl(sbp=0, **out)

def rop_json(binary):
    # Gadget JSON schema:
    # [
    #   {
    #     retaddr: int
    #     size: int
    #     opcodes: [
    #       {
    #         offset: int
    #         size: int
    #         opcode: string
    #         type: string
    #       }
    #     ]
    #   }
    # ]
    return json.loads("\n".join(run_cmd(binary, "/Rj")))

@cache
def rop_gadgets(binary, *regexes, cont=False):
    ilog(f"Searching {binary} for {'; '.join(regexes)} gadgets with r2...")
    gadgets = rop_json(binary)
    results = []

    for gadget in gadgets:
        opcodes = gadget['opcodes']
        end_idx = len(opcodes) - len(regexes)

        for start_idx in range(end_idx + 1):
            idx = start_idx
            size = end_idx - idx
            regexes_use = (regexes + (".*",) * size) if cont else regexes

            offset = opcodes[idx]['offset']
            matches = []

            for regex in regexes_use:
                match = re.fullmatch(regex, opcodes[idx]['opcode'])
                if not match:
                    break
                matches.append(match)
                idx += 1

            if len(matches) == len(regexes_use):
                results.append(Gadget(offset, matches))

    return results

def rop_gadget(binary, *regexes):
    results = rop_gadgets(binary, *regexes)
    if len(results) == 0:
        raise LookupError(f"Could not find gadget for: {'; '.join(regexes)}")
    return results[0]

def get_call_returns(binary,xref_from,xref_to):
    ilog(f'Getting return addresses of calls from {hex(xref_from)} to {hex(xref_to)} in {binary} with r2...')

    cmd_xrefs = f's {hex(xref_from)};af;axq'
    xrefs = run_cmd(binary,cmd_xrefs)
    xrefs = [re.split(r'\s+',x) for x in xrefs]
    xrefs = [x for x in xrefs if int(x[2],0)==xref_to]
    rets = []
    CallRet = nt("CallRet", "xref_from xref_to call_addr ret_addr")
    for x in xrefs:
        cmd_ret = f's {x[0]};so;s'
        ret = run_cmd(binary,cmd_ret)
        rets.append(CallRet(xref_from,xref_to,int(x[0],0),int(ret[0],0)))
    return rets
