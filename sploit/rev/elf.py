from sploit.rev import ldd, r2

class ELF:
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
