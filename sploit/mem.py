class Symtbl:
    def __init__(self, base=0, **kwargs):
        self.__dict__ = {'base' : base, **kwargs}

    def __getattribute__(self, sym):
        a = object.__getattribute__(self, sym)
        if sym in object.__getattribute__(self,'__dict__') and sym != 'base':
            return self.base + a
        else:
            return a

    def addr(self, sym, addr):
        if sym == 'base' : self.base = addr
        else: self.base = addr - object.__getattribute__(self, sym)

