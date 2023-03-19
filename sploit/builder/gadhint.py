from dataclasses import dataclass, field
from sploit.rev.gadget import Gadget

@dataclass
class GadHint:
    """
    User-annotated gadget description object

    gadget (Gadget|int): The gadget being annotated.  May be a Gadget object or
    an offset as an int.

    pops (list[str]): The registers popped by this gadget, in order of
    occurrence.

    movs (dict{str:str}): The register-to-register moves made by this gadget.
    Keys are destination register names, values are source register names.  The
    order given is insignificant.

    imms (dict{str:int}): The immediate-to-register loads made by this gadget.
    Keys are destination register names, values are immediate values.  The order
    given is insignificant.

    writes (dict{str:str}): The register-to-memory moves (stores) made by this
    gadget.  Keys are destination register names (expected to hold memory
    locations), values are source register names (expected to hold direct
    values).  The order given is insignificant.

    requirements (dict{str:int}): The register state that is required before
    this gadget should be executed.  Keys are register names, values are the
    required register values.

    stack (list[int]): A list of words to append to the stack following this
    gadget.  The first element given is nearest to the top of the stack and the
    rest follow in order.

    align (bool): If True, this gadget expects the stack to be aligned prior
    to entry.

    syscall (bool): If True, this gadget contains a syscall instruction.

    spm (int): "Stack pointer move" - The amount the stack pointer is adjusted
    by this gadget.  The effect of executing a terminating "return" instruction
    should not be accounted for.  A value of zero is taken as "unspecified".
    """

    gadget: int = 0
    pops: list = field(default_factory=list)
    movs: dict = field(default_factory=dict)
    imms: dict = field(default_factory=dict)
    writes: dict = field(default_factory=dict)
    requirements: dict = field(default_factory=dict)
    stack: list = field(default_factory=list)
    align: bool = False
    syscall: bool = False
    spm: int = 0

    @property
    def offset(self):
        """Return gadget offset as an integer."""
        return int(self.gadget)

    def __index__(self):
        """Convert object to integer using offset value."""
        return self.offset

    def __add__(self, x):
        """Return new object with adjusted offset."""
        return GadHint(self.gadget + x, self.pops, self.movs, self.imms,
                       self.writes, self.requirements, self.stack, self.align,
                       self.syscall, self.spm)

    def __sub__(self, x):
        """Return new object with adjusted offset."""
        return self + (-x)

    def with_requirements(self, reqs):
        """Return new object with additional requirements."""
        for k, v in reqs.items():
            if self.requirements.get(k, v) != v:
                raise ValueError(
                    f"GadHint: Conflicting gadget requirements: "
                    f"{self.requirements}, {reqs}")

        return GadHint(self.gadget, self.pops, self.movs, self.imms,
                       self.writes, self.requirements | reqs, self.stack,
                       self.align, self.syscall, self.spm)

    def __repr__(self):
        """Return human-readable GadHint."""
        def fmt(name, prop):
            if len(prop) > 0:
                return f", {name}={prop}"
            return ""

        s = hex(self.gadget)
        s = f"Gadget({s})" if type(self.gadget) is Gadget else s
        s += fmt("pops", self.pops)
        s += fmt("movs", self.movs)
        s += fmt("imms", self.imms)
        s += fmt("writes", self.writes)
        s += fmt("requirements", self.requirements)
        s += fmt("stack", self.stack)
        if self.align:
            s += ", align"
        if self.syscall:
            s += ", syscall"
        if self.spm > 0:
            s += f", spm={self.spm}"
        return f"GadHint({s})"
