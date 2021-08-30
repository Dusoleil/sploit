import subprocess
import tempfile
import os

from sploit.log import log

class Comm:
    def __init__(self, backend):
        self.back = backend

    def __del__(self):
        for line in self.back.stdin:
            log(line)

    def read(self, size):
        data = self.back.stdin.read(size)
        log(data)
        return data

    def readline(self):
        data = self.back.stdin.readline()
        log(data)
        return data

    def write(self, data):
        self.back.stdout.write(data)
        self.back.stdout.flush()

    def writeline(self, data):
        self.write(data + b'\n')

class Process:
    def __init__(self, args):
        print(f"Running: {' '.join(args)}")
        self.proc = subprocess.Popen(args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT)
        print(f"PID: {self.proc.pid}")
        self.stdin = self.proc.stdout
        self.stdout = self.proc.stdin

    def __del__(self):
        self.proc.wait()

class Pipes:
    def __init__(self,tmp=None):
        if(tmp == None):
            self.dir = tempfile.TemporaryDirectory()
            dirname = self.dir.name
        else:
            dirname =  os.path.join("/tmp",tmp)
        self.pathin = os.path.join(dirname,"in")
        self.pathout = os.path.join(dirname,"out")
        os.mkfifo(self.pathin)
        os.mkfifo(self.pathout)
        print("Waiting on Target to Connect...")
        print("<"+self.pathin+" >"+self.pathout)
        self.stdout = open(self.pathin,"wb")
        self.stdin = open(self.pathout, "rb")
        print("Connected!")

    def __del__(self):
        self.stdout.close()
        self.stdin.close()
        os.unlink(self.pathin)
        os.unlink(self.pathout)

