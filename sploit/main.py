from argparse import ArgumentParser, REMAINDER
import gc
import tempfile
import traceback

from sploit.comm import *
from sploit.log import *

def print_banner(color, line1='', line2='', line3=''):
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
    parser.add_argument('target', nargs=REMAINDER, help='Target program to exploit')
    args = parser.parse_args()

    if(len(args.target)>0):
        target(args.script, args.target)
    else:
        pipe(args.script)

def pipe(script):
    print_banner(ERROR, line3='Pipe Mode')
    with tempfile.TemporaryDirectory() as tmpdir:
        while(True):
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
        comm.readall()
        return
    except KeyboardInterrupt:
        pass
    except:
        ilog(traceback.format_exc(), end='', color=ERROR)
    finally:
        gc.collect()
    ilog("Script Ended Early!", color=WARNING)
