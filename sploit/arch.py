from collections import namedtuple as nt

def btoi(b, signed=False):
    return int.from_bytes(b, arch.endianness, signed=signed)

def itob(i, signed=False):
    return i.to_bytes(arch.wordsize, arch.endianness, signed=signed)

Arch = nt("Arch", "wordsize  endianness  alignment  nopcode")
x86      = Arch(          4,   'little',        16, b'\x90')
x86_64   = Arch(          8,   'little',        16, b'\x90')
ARM      = Arch(          4,   'little',         8, b'\xe1\xa0\x00\x00')
THUMB    = Arch(          4,   'little',         8, b'\x46\xc0')

arch = x86_64
