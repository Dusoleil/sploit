"""
ROP chain generation utilities

This module contains tools for automating basic return-oriented-programming
workloads, such as loading register values and calling into arbitrary functions
or syscalls.  The tools are currently designed to work on x86 (32 or 64 bit)
and ARM (32 bit only).

The main appeal of the ROP class is the ability to abstract away the manual
construction of ROP chain data, and instead make declarative statements like
"call this function with these arguments."  The ROP class will also utilize its
supplied binary objects to automatically find and use trivial gadgets.

The user is able to provide annotations for more complicated gadgets, which help
instruct the class how to incorporate them into a ROP chain.  This is done with
the GadHint dataclass.  GadHint objects are provided to a ROP instance by
including them in the Symtbl of one of the binary objects it is constructed with.
If applicable, a user-supplied gadget will take precedence over automatic gadget
searching.

See the GadHint class to learn more about the descriptive attributes that are
supported.
"""

from graphlib import TopologicalSorter

from sploit.arch import arch, btoi, itob
from sploit.builder.gadhint import GadHint
from sploit.builder.payload import Payload

class ROP(Payload):
    """
    ROP-enabled payload builder

    POP_MAGIC (int): Magic value used for pop instructions where no specific
    value is required by the user.

    SPM_MAGIC (bytes): Magic value to fill the stack with when the best
    available cleaning gadget is larger than is necessary.

    objects (list[ELF]): The binary objects this ROP instance will consider
    for gadget searching.

    safe_syscalls (bool): If True, require that automatically found syscall
    instructions are immediately followed by a return instruction.

    align_calls (bool): If True, ensure that the stack return address into
    function calls is aligned according to the architecture alignment property.
    Knowledge of alignment is taken from the instance Symtbl's base value.

    clean_stack (bool): If True, attempt to locate a cleaning gadget to "pop"
    stack data that is leftover from a function call.  Required if attempting
    to make multiple calls that involve stack-based arguments.
    """

    POP_MAGIC = 0xdead
    SPM_MAGIC = b'\x69'

    def __init__(self, *objects, safe_syscalls=True, align_calls=True,
                 clean_stack=True, **symbols):
        """Initialize new ROP builder instance."""
        super().__init__(**symbols)
        self.objects = objects
        self.safe_syscalls = safe_syscalls
        self.align_calls = align_calls
        self.clean_stack = clean_stack

    def gadgets(self, *regexes, cont=False):
        """Return a list of matching gadgets, considering all objects."""
        results = []
        for obj in self.objects:
            results += obj.gadgets(*regexes, cont=cont)
        return results

    def gadget(self, *regexes):
        """Return the first matching gadget, considering all objects."""
        for obj in self.objects:
            try:
                return obj.gadget(*regexes)
            except:
                pass
        raise LookupError(
            f"ROP: Need to define gadget symbol for {'; '.join(regexes)}")

    def assign(self, *, sym=None, **sets):
        """
        Insert a ROP chain to control given registers.

        **sets (str:int): Keyword arguments specify register assignments to
        perform with this ROP chain.  Argument names correspond to register
        names.

        sym (str): If given, sym is the symbol name used to refer to the
        inserted data.
        """
        gadget = GadHint(0, requirements=sets)
        return self._start_chain(gadget, sym=self._name("assign", sym))

    def call(self, func, *params, sym=None):
        """
        Insert a ROP chain to call function.

        func (int): Entry address of function to call.
        *params (int): Remaining positional args are passed to func.

        sym (str): If given, sym is the symbol name used to refer to the
        inserted data.
        """
        register_params = dict(zip(arch.funcargs, params))
        stack_params = params[len(register_params):]
        gadget = GadHint(func, requirements=register_params, stack=stack_params,
                         align=self.align_calls)
        return self._start_chain(gadget, sym=self._name("call", sym))

    def syscall(self, *params, sym=None):
        """
        Insert a ROP chain to call kernel.

        *params (int): The first argument is the syscall number.  Remaining
        positional arguments are passed to the syscall.

        sym (str): If given, sym is the symbol name used to refer to the
        inserted data.
        """
        if len(params) > len(arch.kernargs):
            raise TypeError("ROP: Too many arguments passed to syscall. "
                "Target architecture supports up to {len(arch.kernargs)-1}.")

        register_params = dict(zip(arch.kernargs, params))
        gadget = self._get_gadget("syscall", {}).with_requirements(register_params)
        return self._start_chain(gadget, sym=self._name("syscall", sym))

    def memcpy(self, dst, src, *, sym=None):
        """
        Insert a ROP chain to write data into memory.

        dst (int): The destination memory address.
        src (bytes): The content to write.

        sym (str): If given, sym is the symbol name used to refer to the
        inserted data.
        """
        gadgets = []
        for idx in range(0, len(src), arch.wordsize):
            g = self._get_write(dst + idx, btoi(src[idx:idx+arch.wordsize]))
            gadgets.append(g)
        return self._start_chain(*gadgets, sym=self._name("memcpy", sym))

    def _get_hints(self):
        """Return all user-supplied gadget hints."""
        return [h for obj in self.objects for _,h in obj.sym if type(h) is GadHint]

    def _discover_requirements(self, seen, graph, current):
        """
        Populate gadget dependency graph.

        This function recursively looks up gadgets to ensure all necessary
        required gadgets can be found, and stores this information into the
        given graph object.  Established dependencies encode the order that the
        chain builder should attempt to satisfy register requirements.
        Dependency loops are detected by the TopologicalSorter.

        seen (set): Set of (register,value) tuples we have already discovered.
        graph (TopologicalSorter): Dependency graph model object.
        current (GadHint): Current gadget we are processing.
        """
        for r, v in current.requirements.items():
            # We key on register name _and_ value because some gadgets may
            # only be capable of storing specific values in a target register.
            # Requiring a register to store different values may require the
            # use of multiple gadgets.
            if (r, v) not in seen:
                gadget = self._get_gadget(r, current.requirements)

                # Add gadget's requirements to the dependency graph.
                # We say that each requirement is a 'successor' to this
                # current gadget 'r', so that the chain builder will satisfy
                # 'r' first.  This prevents the fulfillment of 'r' from
                # colbbering targets it requires, as the builder will satisfy
                # them afterward.
                for x in gadget.requirements:
                    graph.add(x, r)

                # Treat gadget's load immediates as pseudo-requirements for
                # the sake of target ordering, following the same logic
                # as above.
                for x in gadget.imms:
                    graph.add(x, r)

                # Mark node as visited
                seen.add((r, v))
                self._discover_requirements(seen, graph, gadget)

    def _get_gadget(self, target, sets):
        """
        Get context-specific gadget.

        target (str): Either "ret", "syscall", or the name of a register we
        would like to modify.

        sets (dict{str:int}): The set of other register requirements we are
        trying to fulfill in parallel.  Values may affect the gadget we decide
        to use.
        """
        # First, consider user-provided hints before automatically locating
        # gadgets.
        for hint in self._get_hints():
            # Setup additional requirements based on hint's register moves.
            # If a mov target is in sets, require to set the src to the 'sets'
            # value.
            addl_reqs = { src:sets[dst] for dst, src in hint.movs.items() if dst in sets }
            hint = hint.with_requirements(addl_reqs)

            # Pops will be accounted for by the chain builder.
            # Immediates will be handled by gadget ordering in chain builder.
            # Writes are a non-issue here.

            if hint.syscall:
                # Only consider syscalls if the target is syscall.
                if target == "syscall":
                    return hint
            elif target in hint.imms:
                if hint.imms[target] == sets[target]:
                    return hint
            elif target in hint.pops:
                return hint
            elif target in hint.movs:
                return hint

        # Automatically locate simple gadgets
        if target == "ret":
            return GadHint(self.gadget(arch.ret))

        if target == "syscall":
            insns = [arch.syscall, arch.ret] if self.safe_syscalls else [arch.syscall]
            return GadHint(self.gadget(*insns), syscall=True)

        # target == register
        insns = [ i.format(target) for i in arch.popgad ]
        return GadHint(self.gadget(*insns), pops=[target], spm=arch.wordsize)

    def _get_clean(self, size):
        """
        Get a stack cleaning gadget that moves sp by _at least_ size.

        size (int): Minimum stack pointer move.
        """
        # spm values of zero (the default) can't be trusted, as in this case
        # the user likely hasn't annotated the GadHint properly.  Returning a
        # larger move than requested is fine, since the chain builder can insert
        # junk to be popped.
        for hint in self._get_hints():
            if hint.spm >= size and hint.spm > 0:
                return hint

        results = self.gadgets(*arch.cleangad)
        table = { int(g.asm[0].group(1), 0): g for g in results }
        sizes = sorted([ x for x in table.keys() if x >= size ])

        if len(sizes) > 0:
            return GadHint(table[sizes[0]], spm=sizes[0])

        raise LookupError(
            f"ROP: Need to define a stack move gadget of at least {size}")

    def _get_write(self, dst, src):
        """
        Get a memory write gadget, injected with requirements for user data.

        dst (int): The intended memory write location.
        src (int): The intended value to write.
        """
        # If any exist, take the first write provided by user hints, assuming
        # the user's intent to specifically use _this_ write.  Follow-on gadgets
        # to setup the dst and src registers must be findable.
        for hint in self._get_hints():
            if hint.writes:
                d, s = list(hint.writes.items())[0]
                return hint.with_requirements({d:dst, s:src})

        # Only take an automatic write gadget if we can prove up front that its
        # requirements can be met, otherwise move on.  A later search result may
        # pass the test.
        results = self.gadgets(*arch.writegad)

        for gad in results:
            d = gad.asm[0].group("dst")
            s = gad.asm[0].group("src")

            try:
                # Assert requirements are met.
                gadget = GadHint(gad, writes={d: s}, requirements={d:dst, s:src})
                self._discover_requirements(set(), TopologicalSorter(), gadget)
                return gadget
            except:
                pass

        raise LookupError("ROP: Need to define gadgets for memory write / deps")

    def _start_chain(self, *gadgets, sym=None):
        """
        Insert a generic ROP chain.

        *gadgets (GadHint): Annotated gadgets to prepare a chain from.

        sym (str): If given, sym is the symbol name used to refer to the
        inserted data.
        """
        stack = Payload(base=self.end())
        for g in gadgets:
            self._build_chain(stack, g, {})
        return self.bin(stack(), sym=self._name("gadget", sym))

    def _build_chain(self, stack, gadget, sets):
        """
        Generate chain data for a given ROP gadget.

        This function recursively builds a ROP chain for the given gadget and
        its requirements, storing data in the 'stack' object.

        stack (Payload): Stack data being constructed.
        gadget (GadHint): Current gadget we are processing.

        sets (dict{str:int}): The set of other register requirements we are
        trying to fulfill in parallel.
        """
        # Form a to-do-list of registers from our immediate requirements,
        # attempting to order them such that we avoid overwriting/conflicting
        # values (this may not be possible).
        reqs = gadget.requirements
        graph = TopologicalSorter({ r:set() for r in reqs })
        self._discover_requirements(set(), graph, gadget)
        to_do_list = [ x for x in graph.static_order() if x in reqs ]

        # Start chain by satisfying to-do-list requirements.
        while len(to_do_list) > 0:
            g = self._get_gadget(to_do_list[0], reqs)
            self._build_chain(stack, g, reqs)

            # This gadget may satisfy multiple items in the to-do-list.
            # Specifically, all of its pop and mov targets, and any load
            # immediates that match our requirements.  Non-matching
            # immediates will be handled by a later gadget.
            imms = g.imms.keys() & reqs.keys()
            imms = [ x for x in imms if g.imms[x] == reqs[x] ]
            done = g.pops + list(g.movs) + imms
            to_do_list = [ x for x in to_do_list if x not in done ]

        # Append chain data to execute this gadget, but respect offset == 0
        # as a way to disable this gadget (perform a NULL gadget).
        if gadget.offset != 0:
            # Stack alignment if required.
            if gadget.align:
                align = -stack.end() % arch.alignment
                stack.rep(itob(self._get_gadget("ret", {})), align)

            # "Return address" entry into this gadget.
            stack.ret(gadget.offset)

            # The gadget's "inner stack data" will be values to be popped
            # and additional junk data to be deallocated by the gadget itself.
            sp_dest = len(stack) + gadget.spm
            stack.int(*[ sets.get(p, self.POP_MAGIC) for p in gadget.pops ])
            if gadget.spm > 0:
                stack.pad(sp_dest, self.SPM_MAGIC)

            # The gadget's "outer stack data" will be the additional values
            # explicitly specified by the gadget.  Append a separate gadget
            # to clean up these values.
            if len(gadget.stack) > 0:
                size = len(gadget.stack) * arch.wordsize

                if self.clean_stack:
                    clean = self._get_clean(size)
                    stack.ret(clean)
                    sp_dest = len(stack) + clean.spm
                else:
                    ret = self._get_gadget("ret", {})
                    stack.ret(ret)
                    sp_dest = len(stack) + size

                stack.int(*gadget.stack)
                stack.pad(sp_dest, self.SPM_MAGIC)
