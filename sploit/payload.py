from sploit.arch import arch, itob
from sploit.mem import Symtbl

class Payload:
    MAGIC = b'\xef'

    def __init__(self, **kwargs):
        self.payload = b''
        self.sym = Symtbl(**kwargs)
        self.ctrs = {}

    def __len__(self):
        return len(self.payload)

    def __call__(self, badbytes=b''):
        found = [ hex(x) for x in set(self.payload).intersection(badbytes) ]
        if len(found) > 0:
            raise Exception(f'Payload: bad bytes in content: {found}')
        return self.payload

    def __name(self, kind):
        try: ctr = self.ctrs[kind]
        except: ctr = 0
        self.ctrs[kind] = ctr + 1
        return f'{kind}_{ctr}'

    def __append(self, value, sym):
        setattr(self.sym.map(0), sym, len(self))
        self.payload += value
        return self

    def __prepend(self, value, sym):
        self.sym.adjust(len(value))
        setattr(self.sym.map(0), sym, 0)
        self.payload = value + self.payload
        return self

    def bin(self, *values, sym=None):
        return self.__append(b''.join(values), sym or self.__name('bin'))

    def str(self, *values, sym=None):
        values = [ v.encode() + b'\x00' for v in values ]
        return self.bin(*values, sym=(sym or self.__name('str')))

    def int(self, *values, sym=None, signed=False):
        values = [ itob(v, signed=signed) for v in values ]
        return self.bin(*values, sym=(sym or self.__name('int')))

    def ret(self, *values, sym=None):
        return self.int(*values, sym=(sym or self.__name('ret')))

    def sbp(self, *values, sym=None):
        if len(values) == 0:
            return self.rep(self.MAGIC, arch.wordsize, sym or self.__name('sbp'))
        return self.int(*values, sym=(sym or self.__name('sbp')))

    def rep(self, value, size, sym=None):
        return self.bin(self.__rep_helper(value, size), sym=(sym or self.__name('rep')))

    def pad(self, size, value=None, sym=None):
        return self.bin(self.__pad_helper(size, value), sym=(sym or self.__name('pad')))

    def pad_front(self, size, value=None, sym=None):
        return self.__prepend(self.__pad_helper(size, value), sym or self.__name('pad'))

    def __rep_helper(self, value, size, *, explain=''):
        if size < 0:
            raise Exception(f'Payload: {explain}rep: available space is negative')
        if (size := size / len(value)) != int(size):
            raise Exception(f'Payload: {explain}rep: element does not divide the space evenly')
        return value * int(size)

    def __pad_helper(self, size, value):
        return self.__rep_helper(value or arch.nopcode, size - len(self), explain='pad: ')
