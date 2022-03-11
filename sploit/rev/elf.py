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
