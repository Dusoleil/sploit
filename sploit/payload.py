from sploit.arch import arch, itob
from sploit.mem import Symtbl

class Payload(Symtbl):
    MAGIC = b'\xef'

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self = self._namesp
        self.payload = b''
        self.ctrs = {}

    def __len__(self):
        return len(self._namesp.payload)

    def __call__(self, badbytes=b''):
        self = self._namesp
        found = [ hex(x) for x in set(self.payload).intersection(badbytes) ]
        if len(found) > 0:
            raise Exception(f'Payload: bad bytes in content: {found}')
        return self.payload

    def __name(self, kind):
        self = self._namesp
        try: ctr = self.ctrs[kind]
        except: ctr = 0
        self.ctrs[kind] = ctr + 1
        return f'{kind}_{ctr}'

    def __append(self, value, sym):
        setattr(self, sym, len(self))
        self._namesp.payload += value
        return self

    def __prepend(self, value, sym):
        self.adjust(len(value))
        setattr(self, sym, 0)
        self._namesp.payload = value + self._namesp.payload
        return self

    def bin(self, value, sym=None):
        return self.__append(value, sym or self.__name('bin'))

    def str(self, value, sym=None):
        return self.bin(value.encode()+b'\x00', sym or self.__name('str'))

    def int(self, value, sym=None, signed=False):
        return self.bin(itob(value, signed=signed), sym or self.__name('int'))

    def ret(self, value, sym=None):
        return self.int(value, sym or self.__name('ret'))

    def sbp(self, value=None, sym=None):
        if value is None:
            return self.rep(self.MAGIC, arch.wordsize, sym or self.__name('sbp'))
        return self.int(value, sym or self.__name('sbp'))

    def rep(self, value, size, sym=None):
        return self.bin(self.__rep_helper(value, size), sym or self.__name('rep'))

    def pad(self, size, value=None, sym=None):
        return self.bin(self.__pad_helper(size, value), sym or self.__name('pad'))

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
