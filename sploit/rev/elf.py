"""
Definition of the ELF class
"""

from sploit.rev import ldd, r2
from sploit.arch import lookup_arch
from itertools import zip_longest

class ELF:
    """
    Representation of an ELF binary file.

    This class is effectively a front-end for the r2 module.  Through ELF, you
    can get information about an ELF binary in a convenient, object-oriented
    interface and automate some of your static analysis reverse engineering.

    Because much of the functionality of r2 is cached, much of the functionality
    of ELF is also implicitly cached.  Longer operations like retrieving the
    symbol table or looking up gadgets will be faster on subsequent attempts.
    This is mostly useful when sploit is run from the REPL or in Pipes mode
    where this cache is preserved across script runs.

    Some of the behavior of this class is done upfront while other operations
    are performed lazily.  Retrieving symbols, binary info, security info, and
    the list of library dependencies are all done upfront when the object is
    constructed.

    path (str): Absolute file path to the underlying ELF file.

    sym (Symtbl): A collection of named address offsets exposed through the ELF.

    libs (dict{str:ELF}): A dictionary of ELFs representing linked library
    dependencies of the current ELF. They are indexed by their base filename
    (i.e. elf.libs["libc.so.6"]).  The actual ELF is lazily constructed when it
    is requested. Pretty printing of the libs dict is implemented.

    locals (->Symtbl): A psuedo-namespace to access Symtbls for the local
    variables of functions.  i.e. If a function existed in the elf called foo(),
    you could get a Symtbl of its local variables with elf.locals.foo

    info (->str|int): A psuedo-namespace to access various info about the ELF
    file.  Printing elf.info will pretty-print this info in a tabulated form.

    info.type (str): The type of file.

    info.os (str): The os the binary was compiled for.

    info.baddr (int): The virtual base address of the binary.

    info.arch_string (str): A string given by r2 iI that helps identify the
    architecture the binary was compiled for.

    info.wordsize (int): The natual width of an int on the architecture the
    binary was compiled for.

    info.endianness (str): The byte order of an int on the architecture the
    binary was compiled for.

    security (->bool|str): A psuedo-namespace to access security info about the
    binary.  Printing elf.security will pretty-print this info in a tabulated
    form.

    security.stripped (bool): True if the binary was stripped of debugging
    information, symbols, and strings.

    security.pic (bool): True if the binary's code is position independent.

    security.relro (str): The level of "Relocation Read-Only" that the binary
    was compiled with. Pertains to if the Global Offset Table is read-only.
    This is often "partial" or "full".

    security.relocs (bool): True if the binary uses dynamic runtime relocation.

    security.canary (bool): True if the binary uses stack canaries.

    security.nx (bool): True if the binary does not have stack execution
    privileges.

    security.rpath (str): Runtime library lookup path. If there isn't one, this
    will say "NONE".

    arch (Arch): On Construction, an ELF will automatically try to figure out if
    it was compiled for one of sploit's predefined Arch's. If so, it will set it
    here. Otherwise, this is None.
    """

    def __init__(self, path):
        """
        Construct an ELF.

        path (str): The filepath to the ELF binary file.
        """
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
        """Pretty-print a summary of the ELF."""
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
        # Fancy magic dict of {filename:ELF} which will lazy load the ELF
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
        # Fancy magic class that provides a psuedo-namespace to lookup locals for functions
        def __init__(self, elf):
            self.elf = elf
        def __getattr__(self, sym):
            return r2.get_locals(self.elf.path, getattr(self.elf.sym, sym))

    class __BININFO__:
        # Fancy magic class that provides a psuedo-namespace to get properties of the binary
        def __init__(self, bininfo):
            self.info = {
                    "type"          : bininfo['bintype'],
                    "os"            : bininfo['os'],
                    "baddr"         : bininfo['baddr'],
                    "arch_string"   : bininfo['arch'],
                    "wordsize"      : bininfo['bits']//8,
                    "endianness"    : bininfo['endian'],
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
            self.info = {
                    "stripped"      : bininfo['stripped'],
                    "pic"           : bininfo['pic'],
                    "relro"         : bininfo.get('relro',''),
                    "relocs"        : bininfo['relocs'],
                    "canary"        : bininfo['canary'],
                    "nx"            : bininfo['nx'],
                    "rpath"         : bininfo['rpath'],
                }

    def retaddr(self, caller, callee):
        """
        Returns a list of addresses where a function returns into another
        function at.

        caller (int): Address of the calling function to be returned into.

        callee (int): Address of the function that was called and will return.
        """
        return [c.ret_addr for c in r2.get_call_returns(self.path, caller, callee)]

    def gadgets(self, *regexes, cont=False):
        """
        Returns a list of gadgets that match the given regex list.

        *regexes (str): All positional arguments are treated as regex strings
        for the gadget search.

        cont (bool): If true, this function will return all of the assembly past
        the found gadget up to the next return point.
        """
        return [ self.sym[g] for g in r2.rop_gadgets(self.path, *regexes, cont=cont) ]

    def gadget(self, *regexes):
        """Returns the first gadget found that matches the given regex list."""
        return self.sym[r2.rop_gadget(self.path, *regexes)]
