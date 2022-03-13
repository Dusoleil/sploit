class Symtbl:
    def __init__(self, **kwargs):
        self.__dict__ = {**kwargs}

    def adjust(self, off):
        self.__dict__ = {k:v+off for k,v in self.__dict__.items()}

    def rebase(self, sym):
        self.adjust(-sym)

    def __str__(self):
        return __str__(self,self.__dict__)

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
        s = __str__(self,self.__tbl__.__dict__)
        pos = -1
        for i in range(2):
            pos = s.find('\n',pos+1)
        s = s[:pos] + __tbl_format__.format(hex(self.base),'base') + s[pos:]
        return s

__tbl_format__ = '\n{:<20} {:<20}'
def __str__(self,tbl):
    s = 'symbols: ' + str(len(tbl))
    s += __tbl_format__.format('ADDRESS', 'SYMBOL')
    for sym,off in sorted(tbl.items(),key=lambda x:x[1]):
        s += __tbl_format__.format(hex(getattr(self,sym)),sym)
    return s
