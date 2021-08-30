import argparse
import tempfile

from sploit.comm import *

def main():
    parser = argparse.ArgumentParser(description='Execute Sploit Script Against Target')
    parser.add_argument('-d', '--daemon', action='store_true',
                        help='run in "daemon" mode with pipes instead of a designated target')
    parser.add_argument('script',
                        help='exploit script to run')
    parser.add_argument('target', nargs=argparse.REMAINDER,
                        help='target program to exploit')
    args = parser.parse_args()

    if(len(args.target)>0):
        if(args.daemon):
            print("Target Given. Ignoring Daemon Flag...")
        target(args.script,args.target)
    else:
        if(args.daemon):
            daemon(args.script)
        else:
            pipe(args.script)

def daemon(script):
    print("Running in Pipe Daemon Mode...")
    tmpdir = tempfile.TemporaryDirectory()
    tmp = os.path.split(tmpdir.name)[1]
    while(True):
        runscript(script,Comm(Pipes(tmp)));

def pipe(script):
    print("Running in Pipe Mode...");
    runscript(script,Comm(Pipes()));

def target(script,target):
    print("Running in Target Mode...")
    runscript(script,Comm(Process(target)));

def runscript(script,comm):
    print("Running Script...")
    exec(open(script).read())

