sploit is a process interaction automation tool with software exploitation
focused utilities.  It is designed to abstract and simplify process invocation
to enable exploit code reuse across target sources.  It includes a limited, but
powerful and intuitive set of utilities and syntactic sugar which make writing
exploits quick and straightforward.  This enables rapid prototyping workflows.

Installation
--------------
sploit can be installed to the system with
```
$ pip install .
```

Once installed, sploit can be invoked from the PATH like normal
```
$ sploit exploit.py ./target target_args
```

Usage
------------
sploit has two main modes of operation: Process and Pipes.

A sploit script can be run against a specific command in Process mode.  This
will automatically connect the target's stdio into a handy io object that can
be referenced in the sploit script.
```
$ sploit exploit.py ./target target_args
```

If sploit is run omitting the target, it will launch in Pipes mode.  Here, it
will create temporary FIFOs for stdio which will be tied to the same io object
in the sploit script.  In this way, the same script can be used in both modes
and against any target source regardless of how it exposes its stdio.
```
$ sploit exploit.py
```

When running in Pipes mode, sploit will wait for something to connect on the
FIFOs before actually executing the exploit script.  Once it has finished, it
will go back to waiting and run the script again the next time it connects.
This will loop indefinitely until you give a keyboard interrupt (Ctrl+C).  The
exploit script can be modified between each run without any problems.

The main use case of Pipes mode is when you want to launch the target program
under another program (such as gdb).  This enables a powerful workflow where you
can keep sploit and gdb running, make small alterations to the exploit script,
and re-run the target directly in gdb to see what happens.  This allows for
rapid prototyping.

```
gdb> r </tmp/tmpksakkt8o/in >/tmp/tmpksakkt8o/out
```

You can also directly run sploit scripts with the following shebang
```
#!/usr/bin/env sploit
```
