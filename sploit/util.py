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
