from sploit.rev import ldd, r2
from sploit.arch import lookup_arch
from itertools import zip_longest

class ELF:
    def __init__(self, path):
        self.path = path
        self.sym = r2.get_elf_symbols(self.path)
        try:
            libs = ldd.get_libraries(self.path)
        except:
            libs = {}
        self.libs = self.__LIBS__(libs)
        self.locals = self.__LOCALS__(self)
        bininfo = r2.get_bin_info(self.path)
        self.info = self.__BININFO__(bininfo)
        self.security = self.__SECINFO__(bininfo)
        self.arch = lookup_arch(self.info.arch_string, self.info.wordsize, self.info.endianness)

    def __repr__(self):
        s = 'ELF: '
        s += self.path
        s += f'\n{len(self.sym)} symbols @ {hex(self.sym)}'
        column_fmt = '\n{0:36}{1:36}'
        border = '------------'
        s += column_fmt.format(border,border)
        s += column_fmt.format('Binary Info','Security Info')
        s += column_fmt.format(border,border)
        for line in zip_longest(str(self.info).split('\n'),str(self.security).split('\n'),fillvalue=''):
            s += column_fmt.format(line[0],line[1])
        s += f'\n{border}'
        s += '\nLibraries'
        s += f'\n{border}'
        s += '\n'
        s += str(self.libs)
        return s

    class __LIBS__(dict):
        def __init__(self, libs):
            super().__init__({lib.name:lib.path for lib in libs.values() if lib.path})
        def __getitem__(self, lib):
            get = super().__getitem__
            if(type(get(lib))==str):self[lib] = ELF(get(lib))
            return get(lib)
        def __repr__(self):
            s = ''
            for name,lib in self.items():
                s += '\n' + str(name) + ' => ' + (lib if(type(lib)==str) else str(lib.path))
            return s.strip()

    class __LOCALS__:
        def __init__(self, elf):
            self.elf = elf
        def __getattr__(self, sym):
            return r2.get_locals(self.elf.path, getattr(self.elf.sym, sym))

    class __BININFO__:
        # Fancy magic class that provides a psuedo-namespace to get properties of the binary
        def __init__(self, bininfo):
            self.info = {
                    "type"          : bininfo.bintype,
                    "os"            : bininfo.os,
                    "baddr"         : int(bininfo.baddr,0),
                    "arch_string"   : bininfo.arch,
                    "wordsize"      : int(bininfo.bits)//8,
                    "endianness"    : bininfo.endian,
                }
        def __getattr__(self, k):
            return self.info[k]
        def __repr__(self):
            s = ''
            for name,val in self.info.items():
                if name == 'baddr': val = hex(val)
                s += '\n{0:14}{1}'.format(name,val)
            return s.strip()

    class __SECINFO__(__BININFO__):
        # Fancy magic class that provides a psuedo-namespace to get security properties of the binary
        def __init__(self, bininfo):
            bool = lambda s : s == 'true' or s == 'True'
            self.info = {
                    "stripped"      : bool(bininfo.stripped),
                    "pic"           : bool(bininfo.pic),
                    "relro"         : bininfo.relro,
                    "relocs"        : bool(bininfo.relocs),
                    "canary"        : bool(bininfo.canary),
                    "nx"            : bool(bininfo.nx),
                    "rpath"         : bininfo.rpath,
                }

    def retaddr(self, caller, callee):
        return [c.ret_addr for c in r2.get_call_returns(self.path, caller, callee)]

    def gadgets(self, *regexes, cont=False):
        return r2.rop_gadgets(self.path, *regexes, cont=cont)

    def gadget(self, *regexes):
        return r2.rop_gadget(self.path, *regexes)
