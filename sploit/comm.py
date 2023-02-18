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
    readonwrite = False
    timeout = 250 # milliseconds

    def __init__(self, backend):
        self.back = backend

    def shutdown(self):
        try:
            self.back.stdout.close()
        except BrokenPipeError:
            pass

    def read(self, size):
        data = self.back.stdin.read(size)
        if(data == b''):
            raise BrokenPipeError('Tried to read on broken pipe')
        if self.logonread : ilog(data, file=sys.stdout, color=NORMAL)
        return data

    def readline(self):
        data = self.back.stdin.readline()
        if data.endswith(b'\n'):
            data = data[:-1]
        if(data == b''):
            raise BrokenPipeError('Tried to read on broken pipe')
        if self.logonread : ilog(data, file=sys.stdout, color=NORMAL)
        return data

    def readall(self):
        data = b''
        try:
            for line in self.back.stdin:
                tolog = (line[:-1] if line.endswith(b'\n') else line)
                if self.logonread : ilog(tolog, file=sys.stdout, color=NORMAL)
                data += line
        except KeyboardInterrupt:
            pass
        return data

    def readall_nonblock(self):
        try:
            data = b''
            os.set_blocking(self.back.stdin.fileno(), False)
            poll = select.poll()
            poll.register(self.back.stdin, select.POLLIN)
            while True:
                poll.poll(self.timeout)
                d = self.readall()
                if len(d) == 0: return data
                data += d
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
        if self.readonwrite : self.readall_nonblock()

    def writeline(self, data=b''):
        self.write(data + b'\n')

    def interact(self):
        stdin = sys.stdin.buffer
        event = select.POLLIN

        def readall_stdin():
            for line in stdin:
                self.write(line)

        readtable = {
                self.back.stdin.fileno(): self.readall_nonblock,
                stdin.fileno(): readall_stdin,
        }

        try:
            ilog("<--Interact Mode-->")
            os.set_blocking(stdin.fileno(), False)
            l = self.logonread
            self.logonread = True

            poll = select.poll()
            poll.register(self.back.stdin, event)
            poll.register(stdin, event)

            readtable[self.back.stdin.fileno()]()
            while True:
                for fd, e in poll.poll(self.timeout):
                    if not e & event: return
                    readtable[fd]()
        except KeyboardInterrupt:
            pass
        finally:
            self.logonread = l
            os.set_blocking(stdin.fileno(), True)
            ilog("<--Interact Mode Done-->")

def popen(cmdline=''):
    io = Comm((Process(cmdline.split()) if len(cmdline) > 0 else Pipes()))
    io.readall_nonblock()
    io.readonwrite = True
    return io

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
