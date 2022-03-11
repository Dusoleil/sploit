from sploit.mem import Symtbl
from sploit.arch import arch

import re
from subprocess import run
from collections import namedtuple as nt

def run_cmd(binary,cmd):
    return run(['r2','-q','-c',cmd,'-e','scr.color=false',binary],capture_output=True).stdout.decode('utf-8').split('\n')[:-1]

def get_elf_symbols(elf):
    out = {}
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

    return Symtbl(**out)

def get_locals(binary,func):
    addr = hex(func)
    cmd_locals = f's {func};af;aafr;aaft;afvf'
    out = run_cmd(binary,cmd_locals)
    out = [re.split(r':?\s+',var) for var in out]
    out = {var[1]:-(int(var[0],0)-arch.wordsize) for var in out}
    return Symtbl(**out)

def ret_gadget(binary):
    cmd_ret = '/R/ ret~ret'
    out = run_cmd(binary,cmd_ret)
    out = out[0]
    out = re.split(r'\s+',out)
    out = out[1]
    return int(out,0)

def rop_gadget(binary,gad):
    cmd_gad = f'"/R/q {gad}"'
    out = run_cmd(binary,cmd_gad)
    Gad = nt("Gad", "addr asm")
    out = [Gad(int(gad[:gad.find(':')],0),gad[gad.find(':')+2:]) for gad in out]
    return out

def rop_gadget_exact(binary,gad):
    gads = rop_gadget(binary,gad)
    for g in gads:
        if g.asm[:-1].replace('; ',';') == gad:
            return g

def get_call_returns(binary,xref_from,xref_to):
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
