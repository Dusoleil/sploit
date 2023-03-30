from argparse import ArgumentParser, REMAINDER
import gc
from os.path import isdir
import tempfile
import traceback

from sploit.comm import *
from sploit.log import *
from sploit import __version__

def print_banner(color, line1=__version__, line2='', line3=''):
    ilog()
    ilog(' ░▒█▀▀▀█░▒█▀▀█░▒█░░░░▒█▀▀▀█░▀█▀░▀▀█▀▀    ', end='', color=ALT)
    ilog(line1, color=ALT)
    ilog(' ░░▀▀▀▄▄░▒█▄▄█░▒█░░░░▒█░░▒█░▒█░░░▒█░░    ', end='', color=color)
    ilog(line2, color=ALT)
    ilog(' ░▒█▄▄▄█░▒█░░░░▒█▄▄█░▒█▄▄▄█░▄█▄░░▒█░░    ', end='', color=ALT)
    ilog(line3, color=ALT)
    ilog()

def main():
    parser = ArgumentParser(description='Execute Sploit script against target')
    parser.add_argument('script', help='Exploit script to run')
    parser.add_argument('target', nargs=REMAINDER, help='Target cmdline or pipes directory')
    args = parser.parse_args()

    if len(args.target) == 0:
        with tempfile.TemporaryDirectory() as tmpdir:
            pipe(args.script, tmpdir)
    elif len(args.target) == 1 and isdir(args.target[0]):
        pipe(args.script, args.target[0])
    else:
        target(args.script, args.target)

def pipe(script, tmpdir):
    print_banner(ERROR, line3='Pipe Mode')
    while True:
        try:
            p = Pipes(tmpdir)
        except KeyboardInterrupt:
            break
        runscript(script, Comm(p))
        del p

def target(script, target):
    print_banner(STATUS, line3='Subprocess Mode')
    runscript(script, Comm(Process(target)))

def runscript(script, comm):
    try:
        ilog("Running Script...")
        code = compile(open(script).read(), script, 'exec')
        exec(code, {'io': comm, 'print': elog})
        ilog("Script Finished!")
        return
    except KeyboardInterrupt:
        pass
    except:
        ilog(traceback.format_exc(), end='', color=ERROR)
    finally:
        comm.shutdown()
        comm.readall()
        gc.collect()

    ilog("Script Ended Early!", color=WARNING)
