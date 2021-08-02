#!/bin/bash

#sets up sploit.py to use the input/output of a target program
#after running ./sploit you can launch the target program with
#<spltin ./target_program &>spltout
#also works in gdb
#r <spltin &>spltout
#or run the program in the background and set the gdb wait timer in sploit.py
# <spltin ./target_program &>spltout &
# gdb -p <pid that gets printed out when backgrounding target>

rm spltin 2> /dev/null
rm spltout 2> /dev/null

mkfifo spltin
mkfifo spltout

<spltout tee >(./sploit.py &>spltin) | ./sploitlog.py

rm spltin
rm spltout
