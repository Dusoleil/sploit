import types

class Symtbl:
    def __init__(self, *, base=0, **kwargs):
        object.__setattr__(self, '_namesp', types.SimpleNamespace(base=base,sym={},sub={}))
        for k, v in {**kwargs}.items():
            setattr(self, k, v)

    def __getattr__(self, ident):
        self = self._namesp
        if ident == 'base': return self.base
        off = self.base + self.sym[ident]
        if ident in self.sub: return self.sub[ident].map(off)
        return off

    def __setattr__(self, ident, value):
        if ident in dir(self): raise Exception(f'Symtbl: assignment would shadow non-symbol "{ident}"')
        self = self._namesp
        if ident == 'base':
            self.base = value
        else:
            if type(value) is tuple: self.sub[ident], off = value
            else: off = value
            self.sym[ident] = off - self.base

    def map(self, addr, off=0):
        self = self._namesp
        mm = Symtbl()
        mm._namesp.sym, mm._namesp.sub = self.sym, self.sub
        mm._namesp.base = addr - off
        return mm

    def adjust(self, off):
        self = self._namesp
        for k, v in self.sym.items():
            self.sym[k] = v + off

    def rebase(self, off):
        self.adjust(-off)

    def __str__(_self):
        FMT = '\n{:<20} {:<20}'
        self = _self._namesp

        s  = f'{len(self.sym)} symbols @ {hex(_self.base)}'
        s += FMT.format('ADDRESS', 'SYMBOL')
        for sym, _ in sorted(self.sym.items(), key=lambda x:x[1]):
            addr = getattr(_self, sym)
            if type(addr) is Symtbl:
                s += FMT.format(hex(addr.base), f'[{sym}]')
            else:
                s += FMT.format(hex(addr), sym)
        return s
