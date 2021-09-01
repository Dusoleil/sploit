from functools import partial as bind
import re

def lastline(pred, /, *args, **kwargs):
    s = args[-1]
    args = args[:-1]
    p = bind(pred, *args, **kwargs)
    return p(s[-1])

def contains(regex, s):
    return re.search(regex, s)

def equals(regex, s):
    return re.fullmatch(regex, s)
