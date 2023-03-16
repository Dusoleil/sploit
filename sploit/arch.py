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

    def set(self,new_arch):
        """Copy the given Arch into this instance."""
        if type(new_arch) is not Arch:
            raise TypeError(f'arch: new_arch must be an Arch: {new_arch}')
        self.__dict__.update(new_arch.__dict__)

x86      = Arch( 4, 'little', 16, b'\x90')
x86_64   = Arch( 8, 'little', 16, b'\x90')
ARM      = Arch( 4, 'little',  8, b'\xe1\xa0\x00\x00')
THUMB    = Arch( 4, 'little',  8, b'\x46\xc0')

arch = Arch(**x86_64.__dict__)


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
