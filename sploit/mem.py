class Symtbl:
    __subs__ = {}
    def __init__(self, **kwargs):
        self.__dict__ = {**kwargs}

    def subtable(self, sym, off, table):
        setattr(self, sym, off)
        self.__subs__[sym] = table

    class __InnerTable__:
        def __init__(self,off,tbl):
            self.off = off
            self.tbl = tbl
        def __getattribute__(self,sym):
            if(sym in (['off','tbl'] + __attr_filter__)):
                return object.__getattribute__(self,sym)
            addr = getattr(self.tbl,sym)
            if(type(addr)==int):
                return addr + self.off
            if(type(addr)==self.__class__):
                addr.off += self.off
                return addr
            return addr
        def __setattr__(self,sym,off):
            if(sym in ['off','tbl']):
                return object.__setattr__(self,sym,off)
            return setattr(self.tbl,sym,off-self.off)
        def __str__(self):
            return str(self.tbl)

    def __getattribute__(self, sym):
        addr = object.__getattribute__(self,sym)
        if(sym in (['__subs__'] + __attr_filter__)):
            return addr
        if(sym == 'base'):return 0
        if(sym in self.__subs__):
            return self.__InnerTable__(addr,self.__subs__[sym])
        return addr

    def adjust(self, off):
        self.__dict__ = {k:v+off for k,v in self.__dict__.items()}

    def rebase(self, sym):
        self.adjust(-sym)

    def __str__(self):
        return __str__(self,self.__dict__)

class Memmap:
    def __init__(self, tbl, sym, addr):
        self.__tbl__ = tbl
        self.base = addr - sym

    def __getattribute__(self, sym):
        if(sym in (['__tbl__','base'] + __attr_filter__)):
            return object.__getattribute__(self, sym)
        addr = getattr(self.__tbl__, sym)
        if(type(addr)==Symtbl.__InnerTable__):
            addr.off += self.base
            return addr
        return self.base + addr

    def __setattr__(self, sym, addr):
        if(sym in ['__tbl__','base']):
            return object.__setattr__(self,sym,addr)
        return setattr(self.__tbl__,sym,addr-self.base)

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
        addr = getattr(self,sym)
        if(type(addr)==Symtbl.__InnerTable__):
            s += __tbl_format__.format(hex(addr.off),f'[{sym}]')
        else:
            s += __tbl_format__.format(hex(addr),sym)
    return s

__attr_filter__ = ['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__']
