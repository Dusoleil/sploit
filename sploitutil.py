#!/usr/bin/env python3

import sploitconfig as config
from sploitlog import sploitlog

def btoi(b):
    return int.from_bytes(b,'little')

def itob(i):
    return i.to_bytes(8,'little',signed=True)

class Libc:
    def __init__(self,libc_addr,libc_offset):
        self.libc_base = btoi(libc_addr)-btoi(libc_offset)
    def base(self):
        return itob(self.libc_base)
    def addr(self,offset):
        return itob(self.libc_base + btoi(offset))

def log(s):
    if config.use_popen:
        sploitlog(s)

class Communication:
    def __init__(self,stdin,stdout):
        self.stdin = stdin
        self.stdout = stdout
    def send(self,s):
        self.stdout.write(s)
        self.stdout.flush()
    def recv(self):
        out = self.stdin.readline()
        log(out)
        return out
