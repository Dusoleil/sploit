from sploit.rev import ldd, r2

class ELF:
    def __init__(self, path):
        self.path = path
        self.sym = r2.get_elf_symbols(self.path)
        libs = ldd.get_libraries(self.path)
        self.libs = self.__LIBS__(libs)
        self.locals = self.__LOCALS__(self)

    def __str__(self):
        s = 'ELF: '
        s += self.path
        s += '\nSymbol Table'
        s += '\n------------'
        s += '\n'
        s += str(self.sym)
        s += '\n------------'
        s += '\nLibararies'
        s += '\n------------'
        s += str(self.libs)
        return s

    class __LIBS__(dict):
        def __init__(self, libs):
            super().__init__({lib.name:lib.path for lib in libs.values() if lib.path})
        def __getitem__(self, lib):
            get = super().__getitem__
            if(type(get(lib))==str):self[lib] = ELF(get(lib))
            return get(lib)
        def __str__(self):
            s = ''
            for name,lib in self.items():
                s += '\n' + str(name) + ' => ' + lib if(type(lib)==str) else str(lib.path)
            return s

    class __LOCALS__:
        def __init__(self, elf):
            self.elf = elf
        def __getattribute__(self, sym):
            if(sym=='elf'):return object.__getattribute__(self,sym)
            return r2.get_locals(self.elf.path, getattr(self.elf.sym, sym))

    def retaddr(self, caller, callee):
        return [c.ret_addr for c in r2.get_call_returns(self.path, caller, callee)]

    def retgad(self):
        return r2.ret_gadget(self.path)

    def gad(self, gad):
        return [g.addr for g in r2.rop_gadget(self.path, gad)]

    def egad(self, gad):
        return r2.rop_gadget_exact(self.path, gad).addr
