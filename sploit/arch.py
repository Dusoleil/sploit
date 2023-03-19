"""
Architecture-aware utilities and global architecture config

It is common within sploit and for users of sploit to need different behavior
depending on the architecture of the target.  This module encapsulates those
behaviors and bases them on a global architecture that is also configured here.

Users can set the global arch with arch.set() and all of the methods in this
module will honor it.  An architecture can be defined through the Arch dataclass
and there are also several predefined architecture constants that can be used.
These are accessible by name at module scope. (i.e. sploit.arch.x86_64)

arch (Arch): the architecture config that sploit will use whenever it needs to
know the architecture of the target

DEFAULT_ARCH (Arch): the default architecture that arch is set to
"""

from dataclasses import dataclass

def __define_architectures():
    # All predefined architectures should be listed here
    # These will also be added to the module's namespace
    __arch_list = {
        'x86'     : Arch('x86', 4, 'little', 16,      'ret', 'int 0x80',             b'\x90',   ['pop {}','ret'],             [r'add esp, (\w+)','ret'], [r'mov dword \[(?P<dst>\w+)\], (?P<src>\w+)','ret'], [], ['eax','ebx','ecx','edx','esi','edi','ebp']),
        'x86_64'  : Arch('x86', 8, 'little', 16,      'ret',  'syscall',             b'\x90',   ['pop {}','ret'],             [r'add rsp, (\w+)','ret'], [r'mov qword \[(?P<dst>\w+)\], (?P<src>\w+)','ret'], ['rdi','rsi','rdx','rcx','r8','r9'], ['rax','rdi','rsi','rdx','r10','r8','r9']),
        'ARM'     : Arch('arm', 4, 'little',  8, 'pop {pc}',    'svc 0', b'\xe1\xa0\x00\x00', ['pop {{{}, pc}}'], [r'add sp, sp, ([^r]\w*)','pop {pc}'],  [r'str (?P<src>\w+), \[(?P<dst>\w+)\]','pop {pc}'], ['r0','r1','r2','r3'], ['r7','r0','r1','r2','r3','r4','r5']),
        'THUMB'   : Arch('arm', 4, 'little',  8, 'pop {pc}',    'svc 0',         b'\x46\xc0', ['pop {{{}, pc}}'], [r'add sp, sp, ([^r]\w*)','pop {pc}'],  [r'str (?P<src>\w+), \[(?P<dst>\w+)\]','pop {pc}'], ['r0','r1','r2','r3'], ['r7','r0','r1','r2','r3','r4','r5']),
    }
    globals().update(__arch_list)
    global __arch_lookup
    __arch_lookup = {(a.arch_string, a.wordsize, a.endianness) : a for a in reversed(__arch_list.values())}

@dataclass(frozen=True)
class Arch:
    """
    Dataclass of information about a target architecture

    arch_string (str): string returned by r2 iI in the arch field
    wordsize (int): the width, in bytes, of the natural unit of data
    endianness (str): byte order. either "little" or "big"
    alignment (int): the multiple, in bytes, that return addresses must exist
    on the stack
    ret (str): mnemonic for a "return" instruction
    syscall (str): mnemonic for a "syscall" or "service call" instruction
    nopcode (bytes): the exact bytes of a "do nothing" instruction
    popgad (list[str]): ROP gadget template used to pop a value into a register
    cleangad (list[str]): ROP gadget template used to remove values from the
    stack
    writegad (list[str]): ROP gadget template used to write data to memory
    funcargs (list[str]): function argument registers used by the architecture
    calling convention
    kernargs (list[str]): kernel syscall argument registers
    """

    arch_string: str
    wordsize: int
    endianness: str
    alignment: int
    ret: str
    syscall: str
    nopcode: bytes
    popgad: list
    cleangad: list
    writegad: list
    funcargs: list
    kernargs: list

    def set(self,new_arch):
        """Copy the given Arch into this instance."""
        if type(new_arch) is not Arch:
            raise TypeError(f'arch: new_arch must be an Arch: {new_arch}')
        self.__dict__.update(new_arch.__dict__)
__define_architectures()

DEFAULT_ARCH = x86_64
arch = Arch(**DEFAULT_ARCH.__dict__)

def lookup_arch(arch_string, wordsize, endianness):
    """
    Return an Arch object with the matching search parameters.

    If a predefined Arch matches the specified fields, it will be returned.
    Otherwise, None is returned.

    arch_string (str): The "arch" string returned from r2 iI.
    wordsize (int): The natural width of an int in bytes.
    endianness (str): The order of bytes in an int (either "little" or "big")
    """
    return __arch_lookup.get((arch_string, wordsize, endianness))

def sint(i):
    """Convert given int to signed int of arch.wordsize width."""
    return __int(i, True)

def uint(i):
    """Convert given int to unsigned int of arch.wordsize width."""
    return __int(i, False)

def int8(i):
    """Convert given int to signed 8 bit int."""
    return __int(i, True, 1)

def int16(i):
    """Convert given int to signed 16 bit int."""
    return __int(i, True, 2)

def int32(i):
    """Convert given int to signed 32 bit int."""
    return __int(i, True, 4)

def int64(i):
    """Convert given int to signed 64 bit int."""
    return __int(i, True, 8)

def uint8(i):
    """Convert given int to unsigned 8 bit int."""
    return __int(i, False, 1)

def uint16(i):
    """Convert given int to unsigned 16 bit int."""
    return __int(i, False, 2)

def uint32(i):
    """Convert given int to unsigned 32 bit int."""
    return __int(i, False, 4)

def uint64(i):
    """Convert given int to unsigned 64 bit int."""
    return __int(i, False, 8)

def btoi(b, byteorder=None):
    """Convert given byte array to an int."""
    byteorder = byteorder or arch.endianness
    return int.from_bytes(b, byteorder, signed=False)

def itob(i, width=None, byteorder=None):
    """Convert given int to a byte array."""
    width = width or arch.wordsize
    byteorder = byteorder or arch.endianness
    return __int(i,False,width).to_bytes(width, byteorder, signed=False)

def __int(i, signed=False, width=None):
    # type conversion from int to int of given sign and width
    i = int(i)
    width = width or arch.wordsize
    bits = 8 * width
    if signed:
        sign_bit = 1 << (bits - 1)
        return (i & (sign_bit - 1)) - (i & sign_bit)
    else:
        mask = (1 << bits) - 1
        return i & mask
