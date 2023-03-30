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

The pipe FIFOs are normally located in a temporary directory.  However, if a
directory name is given, sploit will use that location instead.  A particularly
useful way to use this is to store the pipes in the current directory for working
with Docker.
```
$ sploit exploit.py .
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

Docker Image
--------------
In addition to a local pip install, sploit is also deployable via Docker.  Build
the image using the supplied Dockerfile with:
```
$ docker build -t sploit .
```

The container runs in the style of an application, and therefore expects to be
interactive.  Also note that it is useful to mount your working directory in the
container, so that the running sploit instance can actually access your target
files or expose its pipes to you (the default working dir of the container is
/home).  Therefore a basic command to run a containerized sploit would be:
```
$ docker run --rm -it -v $PWD:/home sploit exploit.py ./target target_args
```

The use of Scuba (pip install scuba) is recommended to make using ephemeral,
interactive containers more convenient.  In this case it has the added benefit
of automatically creating and executing within an unprivileged user inside the
container:
```
$ scuba --image sploit exploit.py ./target target_args
```
