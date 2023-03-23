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
    return run_cmd_cached(['r2','-q','-c',cmd,'-e','scr.color=false','-e','rop.len=10','-e','search.in=io.maps.x',binary])

def get_elf_symbols(elf):
    ilog(f'Retrieving symbols of {elf} with r2...')

    base = get_bin_info(elf)['baddr']

    sect = json.loads(run_cmd(elf,'iSj')[0])
    sect = {s['name']:s['vaddr'] for s in sect}

    syms = json.loads(run_cmd(elf,'isj')[0])
    syms = [s for s in syms if s['type'] in ['OBJ', 'FUNC', 'NOTYPE']]

    plt = [s for s in syms if s['is_imported']]
    plt = {sym['realname']:sym['vaddr'] for sym in plt}
    plt = Symtbl(base=sect.get('.plt',0), **plt)

    syms = [s for s in syms if not s['is_imported']]
    syms = {sym['realname']:sym['vaddr'] for sym in syms}
    syms = Symtbl(base=base, **syms)

    got = json.loads(run_cmd(elf,'irj')[0])
    got = {sym['name']:sym['vaddr'] for sym in got if 'name' in sym}
    got = Symtbl(base=sect.get('.got',0), **got)

    strings = json.loads(run_cmd(elf,'izj')[0])
    strings = {s['string']:s['vaddr'] for s in strings}
    strings = Symtbl(base=sect.get('.rodata',0), **strings)

    sect = Symtbl(**sect)
    syms.sect = sect
    syms.imp = plt
    syms.rel = got
    syms.str = strings
    return syms

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
    result_offsets = []
    base = get_bin_info(binary)['baddr']

    for gadget in gadgets:
        opcodes = gadget['opcodes']
        end_idx = len(opcodes) - len(regexes)

        for start_idx in range(end_idx + 1):
            idx = start_idx
            size = end_idx - idx
            regexes_use = (regexes + (".*",) * size) if cont else regexes

            offset = opcodes[idx]['offset'] - base
            if offset in result_offsets:
                continue

            matches = []

            for regex in regexes_use:
                match = re.fullmatch(regex, opcodes[idx]['opcode'])
                if not match:
                    break
                matches.append(match)
                idx += 1

            if len(matches) == len(regexes_use):
                results.append(Gadget(offset, matches))
                result_offsets.append(offset)

    return results

def rop_gadget(binary, *regexes):
    results = rop_gadgets(binary, *regexes)
    if len(results) == 0:
        raise LookupError(f"Could not find gadget for: {'; '.join(regexes)}")
    return results[0]

@cache
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

@cache
def get_bin_info(binary):
    ilog(f'Retrieving binary and security info about {binary} with r2...')

    return json.loads(run_cmd(binary,'iIj')[0])
