import re
from subprocess import run
from collections import namedtuple as nt

def get_libraries(elf):
    out = run(['ldd',elf],capture_output=True).stdout.decode('utf-8').split('\n')[:-1]
    out = [re.split(r'\s+',lib)[1:] for lib in out]
    Lib = nt("Lib", "name path addr")
    out = {l[0]:Lib(l[0],l[0] if l[0][0]=='/' else l[2] if l[1]=='=>' else None,l[-1]) for l in out}
    return out
