from sploit.arch import arch, itob
from sploit.symtbl import Symtbl

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

    def _name(self, kind, sym):
        if sym is not None: return sym
        try: ctr = self.ctrs[kind]
        except: ctr = 0
        self.ctrs[kind] = ctr + 1
        return f'{kind}_{ctr}'

    def _append(self, value, sym):
        (self.sym @ 0)[sym] = len(self)
        self.payload += value
        return self

    def _prepend(self, value, sym):
        self.sym >>= len(value)
        (self.sym @ 0)[sym] = 0
        self.payload = value + self.payload
        return self

    def end(self):
        return self.sym.base + len(self)

    def bin(self, *values, sym=None):
        return self._append(b''.join(values), sym=self._name('bin', sym))

    def str(self, *values, sym=None):
        values = [ v.encode() + b'\x00' for v in values ]
        return self.bin(*values, sym=self._name('str', sym))

    def int(self, *values, sym=None):
        values = [ itob(v) for v in values ]
        return self.bin(*values, sym=self._name('int', sym))

    def int8(self, *values, sym=None):
        values = [ itob(v, 1) for v in values ]
        return self.bin(*values, sym=self._name('int', sym))

    def int16(self, *values, sym=None):
        values = [ itob(v, 2) for v in values ]
        return self.bin(*values, sym=self._name('int', sym))

    def int32(self, *values, sym=None):
        values = [ itob(v, 4) for v in values ]
        return self.bin(*values, sym=self._name('int', sym))

    def int64(self, *values, sym=None):
        values = [ itob(v, 8) for v in values ]
        return self.bin(*values, sym=self._name('int', sym))

    def ret(self, *values, sym=None):
        return self.int(*values, sym=self._name('ret', sym))

    def sbp(self, *values, sym=None):
        if len(values) == 0:
            return self.rep(self.MAGIC, arch.wordsize, sym=self._name('sbp', sym))
        return self.int(*values, sym=self._name('sbp', sym))

    def rep(self, value, size, sym=None):
        return self.bin(self._rep_helper(value, size), sym=self._name('rep', sym))

    def pad(self, size, value=None, sym=None):
        return self.bin(self._pad_helper(size, value), sym=self._name('pad', sym))

    def pad_front(self, size, value=None, sym=None):
        return self._prepend(self._pad_helper(size, value), sym=self._name('pad', sym))

    def _rep_helper(self, value, size, *, explain=''):
        if size < 0:
            raise Exception(f'Payload: {explain}rep: available space is negative')
        if (size := size / len(value)) != int(size):
            raise Exception(f'Payload: {explain}rep: element does not divide the space evenly')
        return value * int(size)

    def _pad_helper(self, size, value):
        return self._rep_helper(value or arch.nopcode, size - len(self), explain='pad: ')
