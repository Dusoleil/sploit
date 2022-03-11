from sploit.rev import ldd, r2

__ELF_CACHE__ = {}

def ELF(path):
    if path in __ELF_CACHE__:
        return __ELF_CACHE__[path]
    else:
        elf = __ELF__(path)
        __ELF_CACHE__[path] = elf
        return elf

class __ELF__:
    def __init__(self, path):
        self.path = path
        self.sym = r2.get_elf_symbols(self.path)
        libs = ldd.get_libraries(self.path)
        self.libs = {lib.name:ELF(lib.path) for lib in libs.values() if lib.path}
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
        for name,lib in self.libs.items():
            s += '\n' + str(name) + ' => ' + str(lib.path)
        return s

    class __LOCALS__:
        def __init__(self,elf):
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
