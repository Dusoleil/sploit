class Symtbl:
    def __init__(self, **kwargs):
        self.__dict__ = {**kwargs}

    def __str__(self):
        tbl_format = '\n{:<20} {:<20}'
        s = 'len: ' + str(len(self.__dict__))
        s += tbl_format.format('ADDRESS', 'SYMBOL')
        for sym,addr in sorted(self.__dict__.items(),key=lambda x:x[1]):
            s += tbl_format.format(hex(addr),sym)
        return s

class Memmap:
    def __init__(self, tbl, sym, addr):
        object.__setattr__(self,'__tbl__', tbl)
        base = addr if sym == 'base' else addr - getattr(self.__tbl__, sym)
        object.__setattr__(self,'base', base)

    def __getattribute__(self, sym):
        if sym == '__tbl__' or sym == 'base':
            return object.__getattribute__(self, sym)
        a = getattr(self.__tbl__, sym)
        return self.base + a

    def __setattr__(self, k, v):
        raise TypeError('Memmaps are Read-Only! Modify offsets with Symtbl instead!')

    def __str__(self):
        tbl_format = '\n{:<20} {:<20}'
        s = 'len: ' + str(len(self.__tbl__.__dict__)+1)
        s += tbl_format.format('ADDRESS', 'SYMBOL')
        s += tbl_format.format(hex(self.base),'base')
        for sym,addr in sorted(self.__tbl__.__dict__.items(),key=lambda x:x[1]):
            s += tbl_format.format(hex(addr+self.base),sym)
        return s
