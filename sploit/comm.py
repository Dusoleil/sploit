import subprocess
import tempfile
import os
import sys
import select

from sploit.log import *
from sploit.until import bind

class Comm:
    logonread = True
    logonwrite = False
    flushonwrite = True
    timeout = 0.25 # seconds

    def __init__(self, backend):
        self.back = backend

    def shutdown(self):
        self.back.stdout.close()

    def read(self, size):
        data = os.read(self.back.stdin.fileno(), size)
        if(data == b''):
            raise BrokenPipeError('Tried to read on broken pipe')
        if self.logonread : ilog(data, file=sys.stdout, color=NORMAL)
        return data

    def readline(self):
        data = self.back.stdin.readline()
        if(data == b''):
            raise BrokenPipeError('Tried to read on broken pipe')
        if self.logonread : ilog(data, file=sys.stdout, color=NORMAL)
        return data

    def readall(self):
        data = b''
        try:
            for line in self.back.stdin:
                if self.logonread : ilog(line, file=sys.stdout, color=NORMAL)
                data += line
        except KeyboardInterrupt:
            pass
        return data

    def readall_nonblock(self):
        try:
            os.set_blocking(self.back.stdin.fileno(), False)
            poll = select.poll()
            poll.register(self.back.stdin, select.POLLIN)
            poll.poll(self.timeout)
            return self.readall()
        finally:
            os.set_blocking(self.back.stdin.fileno(), True)

    def readuntil(self, pred, /, *args, **kwargs):
        data = b''
        pred = bind(pred, *args, **kwargs)
        l = self.logonread
        self.logonread = False
        try:
            while(True):
                data += self.read(1)
                if(pred(data)):
                    break
        finally:
            self.logonread = l
        if self.logonread : ilog(data, file=sys.stdout, color=NORMAL)
        return data

    def readlineuntil(self, pred, /, *args, **kwargs):
        dataarr = []
        pred = bind(pred, *args, **kwargs)
        while(True):
            dataarr.append(self.readline())
            if(pred(dataarr)):
                break
        return dataarr

    def write(self, data):
        self.back.stdout.write(data)
        if self.flushonwrite : self.back.stdout.flush()
        if self.logonwrite : ilog(data, file=sys.stdout, color=ALT)

    def writeline(self, data):
        self.write(data + b'\n')

    def interact(self):
        ilog("<--Interact Mode-->")
        stdin = sys.stdin.buffer
        os.set_blocking(self.back.stdin.fileno(), False)
        os.set_blocking(stdin.fileno(), False)
        poll = select.poll()
        poll.register(self.back.stdin, select.POLLIN)
        poll.register(stdin, select.POLLIN)
        brk = False
        def readall(read, write):
            while(True):
                data = read()
                if(data == b''):
                    break
                write(data)
        def writeinput(write):
            ilog(write, file=sys.stdout, color=NORMAL)
        readtable = {
                stdin.fileno() : lambda : readall(stdin.readline, self.write),
                self.back.stdin.fileno() : lambda : readall(self.back.stdin.readline, writeinput)
        }
        readtable[self.back.stdin.fileno()]()
        while(not brk):
            try:
                ioevents = poll.poll(100)
                for ev in ioevents:
                    if(ev[1] & select.POLLIN):
                        readtable[ev[0]]()
                    else:
                        brk = True
                        break
            except KeyboardInterrupt:
                break
        os.set_blocking(self.back.stdin.fileno(), True)
        os.set_blocking(stdin.fileno(), True)
        ilog("<--Interact Mode Done-->")

class Process:
    def __init__(self, args):
        ilog(f"Running: {' '.join(args)}")
        self.proc = subprocess.Popen(args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                preexec_fn=lambda : os.setpgrp())
        ilog(f"PID: {self.proc.pid}")
        self.stdin = self.proc.stdout
        self.stdout = self.proc.stdin

    def __del__(self):
        if getattr(self, 'proc', None) == None : return
        if(self.proc.poll() != None):
            return
        try:
            ilog("Waiting on Target Program to End...")
            ilog("Press Ctrl+C to Forcefully Kill It...")
            self.proc.wait()
        except KeyboardInterrupt:
            self.proc.kill()

class Pipes:
    def __init__(self, tmp=None):
        if(tmp == None):
            self.dir = tempfile.TemporaryDirectory()
            dirname = self.dir.name
        else:
            if(not os.path.exists(tmp)):
                os.mkdir(tmp)
            dirname = tmp
        self.pathin = os.path.join(dirname, "in")
        self.pathout = os.path.join(dirname, "out")
        os.mkfifo(self.pathin)
        os.mkfifo(self.pathout)
        ilog("Waiting on Target to Connect...", file=sys.stdout)
        ilog(f"<{self.pathin} >{self.pathout}", file=sys.stdout)
        self.stdout = open(self.pathin, "wb")
        self.stdin = open(self.pathout, "rb")
        ilog("Connected!")

    def __del__(self):
        try:
            if getattr(self,'stdout',None) : self.stdout.close()
            if getattr(self,'stdin',None) : self.stdin.close()
        except BrokenPipeError:
            pass
        if getattr(self,'pathin',None) and os.path.exists(self.pathin) : os.unlink(self.pathin)
        if getattr(self,'pathout',None) and os.path.exists(self.pathout) : os.unlink(self.pathout)
