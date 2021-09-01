import subprocess
import threading
import tempfile
import os
import sys
import select
import signal

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

    def readuntil(self,pred):
        data = b''
        while(not pred(data)):
            data += self.back.stdin.read(1)
        log(data)
        return data

    def readlineuntil(self,pred):
        data = b''
        while(not pred(data)):
            data = self.back.stdin.readline()
            log(data)
        return data

    def write(self, data):
        self.back.stdout.write(data)
        self.back.stdout.flush()

    def writeline(self, data):
        self.write(data + b'\n')

    def interact(self):
        print("<--Interact Mode-->")
        syncstop = threading.Event()
        def readloop():
            poll = select.poll()
            poll.register(self.back.stdin)
            def readall():
                while(True):
                    data = self.back.stdin.readline()
                    if(data == b''):
                        break
                    log(data)
            while not syncstop.isSet():
                readall()
                dat = poll.poll(100)
                if(len(dat)>0):
                    if(dat[0][1] & select.POLLIN):
                        readall()
                    else:
                        syncstop.set()
        os.set_blocking(self.back.stdin.fileno(),False)
        readthread = threading.Thread(target=readloop,daemon=True)
        readthread.start()
        stdin = sys.stdin.buffer
        signal.signal(signal.SIGALRM,lambda: 0)
        while not syncstop.isSet():
            try:
                signal.alarm(1)
                data = stdin.readline()
                if(data and not syncstop.isSet()):
                    self.write(data)
                else:
                    break
            except TypeError:
                pass
            except KeyboardInterrupt:
                break
        signal.alarm(0)
        syncstop.set()
        readthread.join()
        os.set_blocking(self.back.stdin.fileno(),True)
        print("<--Interact Mode Done-->")

class Process:
    def __init__(self, args):
        print(f"Running: {' '.join(args)}")
        self.proc = subprocess.Popen(args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                preexec_fn=lambda : os.setpgrp())
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
            if(not os.path.exists(tmp)):
                os.mkdir(tmp)
            dirname = tmp
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

