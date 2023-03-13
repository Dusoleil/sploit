"""
Architecture-aware utilities and global architecture config

It is common within sploit and for users of sploit to need different behavior
depending on the architecture of the target.  This module encapsulates those
behaviors and bases them on a global architecture that is also configured here.

Users can set the global arch with arch.set() and all of the methods in this
module will honor it.  An architecture can be defined through the Arch dataclass
and there are also several predefined architecture constants that can be used.

arch (Arch): the architecture config that sploit will use whenever it needs to
know the architecture of the target

predefined architectures:
    x86
    x86_64
    ARM
    THUMB
"""

from dataclasses import dataclass

def btoi(b, signed=False):
    return int.from_bytes(b, arch.endianness, signed=signed)

def itob(i, signed=False):
    return i.to_bytes(arch.wordsize, arch.endianness, signed=signed)

@dataclass(frozen=True)
class Arch:
    """
    Dataclass of information about a target architecture

    wordsize (int): the width, in bytes, of the natural unit of data
    endianness (str): byte order. either "little" or "big"
    alignment (int): the multiple, in bytes, that return addresses must exist
    on the stack
    nopcode (bytes): the exact bytes of a "do nothing" instruction
    """

    wordsize: int
    endianness: str
    alignment: int
    nopcode: bytes

    def set(self,k):
        """Copy the given Arch into this instance."""
        self.__dict__.update(k.__dict__)

x86      = Arch( 4, 'little', 16, b'\x90')
x86_64   = Arch( 8, 'little', 16, b'\x90')
ARM      = Arch( 4, 'little',  8, b'\xe1\xa0\x00\x00')
THUMB    = Arch( 4, 'little',  8, b'\x46\xc0')

arch = Arch(**x86_64.__dict__)
