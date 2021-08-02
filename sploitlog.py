#!/usr/bin/env python3

import os

import sploitconfig as config

#this function does not look at the run mode and will write to stdout regardless
#use sploitutil.log instead
def sploitlog(s):
    if config.log_encoding != '':
        s = s.decode(config.log_encoding)
    print(s)

if __name__ == '__main__':
    stdin = os.fdopen(0,"rb")
    for s in stdin:
        sploitlog(s)
