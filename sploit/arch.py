def btoi(b, signed=False):
    return int.from_bytes(b, arch.endianness, signed=signed)

def itob(i, signed=False):
    return i.to_bytes(arch.wordsize, arch.endianness, signed=signed)

class Arch:
    def __init__(self, wordsize, endianness, alignment, nop):
        self.wordsize = wordsize
        self.endianness = endianness
        self.alignment = alignment
        self.nop = nop

archx86 = Arch(
    wordsize = 4,
    endianness = "little",
    alignment = 16,
    nop = b'\x90'
)

archx86_64 = Arch(
    wordsize = 8,
    endianness = "little",
    alignment = 16,
    nop = b'\x90'
)

arch = archx86_64