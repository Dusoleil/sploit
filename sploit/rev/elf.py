from sploit.rev import ldd, r2

class ELF:
    def __init__(self, path):
        self.path = path
        self.sym = r2.get_elf_symbols(self.path)
        libs = ldd.get_libraries(self.path)
        self.libs = self.__LIBS__(libs)
        self.locals = self.__LOCALS__(self)

    def __repr__(self):
        s = 'ELF: '
        s += self.path
        s += '\n------------'
        s += '\nSymbol Table'
        s += '\n------------'
        s += '\n'
        s += str(self.sym)
        s += '\n------------'
        s += '\nLibraries'
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
        def __repr__(self):
            s = ''
            for name,lib in self.items():
                s += '\n' + str(name) + ' => ' + (lib if(type(lib)==str) else str(lib.path))
            return s

    class __LOCALS__:
        def __init__(self, elf):
            self.elf = elf
        def __getattr__(self, sym):
            return r2.get_locals(self.elf.path, getattr(self.elf.sym, sym))

    def retaddr(self, caller, callee):
        return [c.ret_addr for c in r2.get_call_returns(self.path, caller, callee)]

    def gadgets(self, *regexes, cont=False):
        return r2.rop_gadgets(self.path, *regexes, cont=cont)

    def gadget(self, *regexes):
        return r2.rop_gadget(self.path, *regexes)
