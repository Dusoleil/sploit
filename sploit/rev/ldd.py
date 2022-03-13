from sploit.util import run_cmd_cached

import re
from collections import namedtuple as nt

def get_libraries(elf):
    out = run_cmd_cached(['ldd',elf])
    out = [re.split(r'\s+',lib)[1:] for lib in out]
    Lib = nt("Lib", "name path addr")
    out = {l[0]:Lib(l[0],l[0] if l[0][0]=='/' else l[2] if l[1]=='=>' else None,l[-1]) for l in out}
    return out
