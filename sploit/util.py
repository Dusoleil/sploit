from subprocess import run

def run_cmd(cmd):
    return run(cmd,capture_output=True).stdout.decode('utf-8').split('\n')[:-1]

__RUN_CACHE__ = {}
def run_cmd_cached(cmd):
    key = ''.join(cmd)
    if key in __RUN_CACHE__:
        return __RUN_CACHE__[key]
    else:
        result = run_cmd(cmd)
        __RUN_CACHE__[key] = result
        return result

__attr_filter__ = ['__class__', '__delattr__', '__dict__', '__dir__', '__doc__',
        '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__',
        '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__',
        '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__',
        '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__',
        '__weakref__']

