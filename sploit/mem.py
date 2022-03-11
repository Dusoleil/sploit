class Symtbl:
    def __init__(self, **kwargs):
        self.__dict__ = {**kwargs}


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
