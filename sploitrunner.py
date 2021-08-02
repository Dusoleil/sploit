#!/usr/bin/env python3

import os
import sys
import subprocess
import time

import sploitconfig as config
import sploitutil as util

#infrastructure to run sploit
#if sploit is called with command line arguments,
#it will use them to call the target program with popen
#otherwise, sploit will use stdin/stdout
#you can use sploitpipe to run sploit with pipes spltin/spltout
#which can be used with the target program
#<spltin ./target &>spltout
#or from within gdb
#r <spltin &>spltout
def runsploit(sploit):
    if config.use_popen:
        print(sys.argv[1:])
        p = subprocess.Popen(sys.argv[1:],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)

    stdin = p.stdout if config.use_popen else os.fdopen(0,"rb")
    stdout = p.stdin if config.use_popen else os.fdopen(1,"wb")

    if config.wait_for_gdb > 0:
        time.sleep(config.wait_for_gdb)

    #exec custom sploit
    sploit(stdin,stdout)

    #read anything else out and wait for termination
    for line in stdin:
        util.log(line)
    if config.use_popen:
        p.wait()
