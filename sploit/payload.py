from sploit.arch import arch, itob
from sploit.mem import Symtbl

# Users can set this to the (absolute) address of a 'ret' ROP gadget.  Some
# features may require it.
RETGADGET : int = None

class Placeholder(bytearray):
    def __init__(self, text='_unnamed_'):
        self += bytearray(itob(0))
        self.text = text

class Payload:
    def __init__(self, size=0, base=0, **kwargs):
        self.payload = b''
        self.size = size
        self.alignstart = None
        self.tab = Symtbl(base=base, **kwargs)

    def __len__(self):
        return len(self.payload)

    def __getattr__(self, sym):
        return getattr(self.tab, sym)

    def data(self, x, sym='_'):
        off = len(self)
        self.payload += x
        setattr(self.tab, sym, off)
        return getattr(self.tab, sym)

    def value(self, x, sym='_', signed=False):
        return self.data(itob(x, signed=signed), sym=sym)

    def ret(self, x, sym='_'):
        self.align()
        return self.value(x, sym=sym)

    def stuff(self, x, size, sym='_', *, explain=''):
        if size >= 0:
            if (size := size / len(x)) == int(size):
                if size == 0 or not isinstance(x, Placeholder):
                    return self.data(x * int(size), sym=sym)

                raise Exception(explain+"Can not stuff payload: "
                        f"Placeholder for {x.text} detected")
            raise Exception(explain+"Can not stuff payload: "
                    "Element does not divide the space evenly")
        raise Exception(explain+"Can not stuff payload: "
                "Available space is negative")

    def pad(self, x=None, sym='_'):
        size = self.size - len(self)
        return self.stuff((x or arch.nopcode), size, sym=sym,
                explain='Error padding payload: ')

    def align(self, x=None, sym='_'):
        if self.alignstart is None:
            self.alignstart = len(self)

        retgad = (itob(RETGADGET) if RETGADGET else Placeholder('ret gadget'))
        size = (self.alignstart - len(self)) % arch.alignment
        return self.stuff((x or retgad), size, sym=sym,
                explain='Error aligning payload: ')
