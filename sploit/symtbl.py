"""
Symtbl data structure

A Symtbl (symbol table) is an associative data container intended to model
arbitrary memory layouts, such as structure definitions or memory-mapped
objects.  Elements may be accessed via subscript or attribute notation.

A Symtbl is essentially a dictionary, in which each key (symbol name string)
is associated with an offset value.  A special key "base" represents the
base or starting address of the overall table in memory.  Whenever offset
values are accessed, they are adjusted relative to the table's base value.
This enables the primary function of Symtbl objects: the ability to resolve
mapped, or absolute, addresses of objects in memory.

Therefore, even though a Symtbl internally tracks symbol offsets, the apparent
value of any symbol will always be its offset plus the table's base address.
The table's base address will also be subtracted from values being stored in
the table, as the provided value is assumed to be mapped in the same manner as
the table itself.

    s = Symtbl()
    s.a = 10
    s.b = 20
    print(s.a, s.b)         # "10 20"
    s.base = 100
    print(s.a, s.b)         # "110 120"
    s.c = 150
    s.base = 10
    print(s.a, s.b, s.c)    # "20 30 60"

A Symtbl's base value may be changed at any time, and this will affect the
interpretation of offsets as described above.  However, one may also create a
remapped version of a Symtbl (without modifying the original) using the '@'
operator.  This new object will have the base value given on the right hand
side of the '@' and its collection of symbols is referentially linked to the
source object, meaning changes to symbol entries will be visible in both
objects.

    s1 = Symtbl()
    s1.a = 10
    s2 = s1 @ 1000
    print(s1.a, s2.a)       # "10 1010"
    s2.b = 1234
    print(s1.b, s2.b)       # "234 1234"

Symtbl's are also nestable, to support modeling composite memory layouts.  If
a symbol's value is assigned to another Symtbl object, rather than an integer
offset, the child object's base value serves as its offset in the parent
Symtbl.  Symbols on the child object may then be accessed recursively from the
parent's scope.  If the parent has a non-zero base, it adjusts the offsets
interpreted in the child.

    child = Symtbl()
    child.a = 1
    child.b = 2
    parent = Symtbl()
    parent.nested = child @ 70
    print(parent.nested.a, parent.nested.b)     # "71 72"

A Symtbl will allow you to uniformly adjust all offsets contained, while leaving
the base value the same, using the '<<' and '>>' operators.  A custom
"rebase" operation is also available via the "%" operator.  A rebase applies
a uniform shift, such that the right hand side offset operand ends up coinciding
with the Symtbl base address.

    s = Symtbl()
    s.a = 1
    s.b = 2
    s.c = 3
    s.d = 4
    s.base = 1000
    s %= s.c                    # rebase at symbol 'c'
    print(s.a, s.b, s.c, s.d)   # "998 999 1000 1001"
"""

def Symtbl(*, base=0, **symbols):
    """
    Create a new Symtbl object

    Return an empty Symtbl or, optionally, one initialized with the given
    symbol values.  Arguments _must_ be keyword arguments.

    Users should call this function instead of attempting to construct the
    Symtbl class.  Construction is implemented via a normal function to prevent
    any argument name from conflicting with __init__'s bound instance parameter.
    """
    self = SymtblImpl({}, 0, base)
    for k, v in symbols.items():
        self[k] = v
    return self

class SymtblImpl:
    """Symtbl implementation class"""

    def __init__(self, entries, adjust, base):
        """Construct Symtbl from instance data"""
        object.__setattr__(self, "__entries__", entries)
        object.__setattr__(self, "__adjust__",  adjust)
        object.__setattr__(self, "base", base)

    def __index__(self):
        """Convert object to integer using base value"""
        return self.base

    def __matmul__(self, base):
        """Create remapped version of object at absolute base"""
        return SymtblImpl(self.__entries__, self.__adjust__, int(base))

    def __add__(self, offset):
        """Create remapped version of object at relative base"""
        return self @ (self.base + offset)

    def __sub__(self, offset):
        """Create remapped version of object at relative base"""
        return self @ (self.base - offset)

    def __rshift__(self, offset):
        """Create symbol adjusted version of object"""
        return SymtblImpl(self.__entries__, self.__adjust__ + int(offset), self.base)

    def __lshift__(self, offset):
        """Create symbol adjusted version of object"""
        return self >> (-offset)

    def __mod__(self, offset):
        """Create symbol rebased version of object"""
        return self >> (self.base - offset)

    def __getattr__(self, symbol):
        """Return symbol offset or subtable via pseudo-attribute"""
        return self[symbol]

    def __setattr__(self, symbol, value):
        """Set symbol offset or subtable via pseudo-attribute"""
        self[symbol] = value

    def __delattr__(self, symbol):
        """Unset symbol via pseudo-attribute"""
        del self[symbol]

    def __len__(self):
        """Return number of defined symbols"""
        return len(self.__entries__)

    def __getitem__(self, symbol):
        """Return symbol offset or subtable via subscript"""
        if symbol == "base":
            return self.base
        return self.__entries__[symbol] + (self.base + self.__adjust__)

    def __setitem__(self, symbol, value):
        """Set symbol offset or subtable via subscript"""
        if symbol == "base":
            object.__setattr__(self, "base", int(value))
        elif symbol in dir(self):
            raise KeyError(f"Symtbl: name '{symbol}' is reserved")
        else:
            self.__entries__[symbol] = value - (self.base + self.__adjust__)

    def __delitem__(self, symbol):
        """Unset symbol via subscript"""
        del self.__entries__[symbol]

    def __iter__(self):
        """Iterate over table entries as key:value tuples, like dict.items()"""
        return iter({ k: self[k] for k in self.__entries__ }.items())

    def __contains__(self, symbol):
        """Test symbol name membership in table"""
        return symbol in self.__entries__

    def __repr__(self):
        """Return string representation of Symtbl"""
        return str(self)

    def __str__(self):
        """Return string representation of Symtbl"""
        FMT = "\n{:<20} {:<20}"
        s = f"{len(self)} symbols @ {hex(self)}"
        s += FMT.format("ADDRESS", "SYMBOL")
        for symbol, offset in sorted(self, key=lambda v: int(v[1])):
            disp = f"[{symbol}]" if type(offset) is SymtblImpl else symbol
            s += FMT.format(hex(offset), disp)
        return s
