#!/usr/bin/env python3

import sys

#if given a program name on the command line, we'll use popen
#otherwise, we use stdin/stdout
#in the latter case, you can use sploitpipe to set up spltin and spltout
use_popen = len(sys.argv) > 1
#sleep for this many seconds to give time to attach gdb
wait_for_gdb = 0
#will decode output with this encoding for printing
#or if empty, will print as bytes
log_encoding = ''#'utf-8'
