from argparse import ArgumentParser, REMAINDER
import gc
import tempfile
import traceback

from sploit.comm import *

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
    print("Running in Pipe Mode...")
    with tempfile.TemporaryDirectory() as tmpdir:
        while(True):
            try:
                p = Pipes(tmpdir)
            except KeyboardInterrupt:
                break
            runscript(script, Comm(p))
            del p

def target(script, target):
    print("Running in Target Mode...")
    runscript(script, Comm(Process(target)))

def runscript(script, comm):
    try:
        print("Running Script...")
        code = compile(open(script).read(), script, 'exec')
        exec(code, {'io': comm})
        print("Script Finished!")
        comm.readall()
        return
    except KeyboardInterrupt:
        pass
    except:
        traceback.print_exc()
    finally:
        gc.collect()
    print("Script Ended Early!")
