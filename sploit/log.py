import codecs
import sys

# https://docs.python.org/3/library/codecs.html#standard-encodings
ENCODING = None

ERROR   = 31
WARNING = 33
STATUS  = 32
NORMAL  =  0
ALT     = 90

def enc_value(value, enc):
    if type(value) is bytes:
        if enc is not None:
            value = codecs.encode(value, enc)
        elif ENCODING is not None:
            value = codecs.encode(value, ENCODING)
        value = str(value)[2:-1] # strip b''
    return str(value)

def generic_log(*values, sep, end, file, flush, enc, color):
    string = sep.join([ enc_value(x, enc) for x in values ])
    print(f'\033[{color}m{string}\033[0m', end=end, file=file, flush=flush)

# For library internal use
def ilog(*values, sep=' ', end='\n', file=sys.stderr, flush=True, enc=None, color=STATUS):
    generic_log(*values, sep=sep, end=end, file=file, flush=flush, enc=enc, color=color)

# For external use in user script (via print = elog)
def elog(*values, sep=' ', end='\n', file=sys.stdout, flush=True, enc=None, color=ALT):
    generic_log(*values, sep=sep, end=end, file=file, flush=flush, enc=enc, color=color)
