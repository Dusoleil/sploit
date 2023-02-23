from os import path
from subprocess import run

def run_cmd(cmd,cwd=None):
    return run(cmd,cwd=cwd,capture_output=True,text=True,check=True).stdout.split('\n')[:-1]

__RUN_CACHE__ = {}
def run_cmd_cached(cmd,cwd=None):
    key = ''.join(cmd)
    if key in __RUN_CACHE__:
        return __RUN_CACHE__[key]
    else:
        result = run_cmd(cmd,cwd)
        __RUN_CACHE__[key] = result
        return result

#try to get the version through git
def git_version():
    try:
        cwd = path.dirname(path.realpath(__file__))
        version = run_cmd(["git","describe","--always","--first-parent","--dirty"],cwd=cwd)[0]
        #PEP440 compliance
        version = version.replace('-','+',1).replace('-','.')
        return version
    except:
        return "0+unknown.version"
