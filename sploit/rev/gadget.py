from dataclasses import dataclass, field

@dataclass
class Gadget:
    """
    Basic gadget description object

    offset (int): The location this gadget is found at.  What `offset` is
    relative to depends on context.

    asm (list[re.Match]): A list of assembly instructions matched by the gadget
    search query.
    """

    offset: int = 0
    asm: list = field(default_factory=list)

    def __index__(self):
        """Convert object to integer using offset value."""
        return self.offset

    def __add__(self, x):
        """Return new object with adjusted offset."""
        return Gadget(self.offset + x, self.asm)

    def __sub__(self, x):
        """Return new object with adjusted offset."""
        return self + (-x)

    def __repr__(self):
        """Return human-readable Gadget."""
        s = hex(self.offset)
        if len(self.asm) > 0:
            asm = "; ".join([ m.string for m in self.asm ])
            s += f", '{asm}'"
        return f"Gadget({s})"
