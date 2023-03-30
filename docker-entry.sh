#!/bin/sh
ENTRYPOINT=sploit

# We want to support scuba as a convenient front-end for invoking containers.
# However, scuba doesn't actually pass arguments to the image entrypoint
# correctly.  Instead, it treats the entrypoint as a shell equivalent, and
# instructs it to run its own generated command script.  We can't determine
# whether scuba is invoked with a command or a multi-line alias, so we just grab
# the last line from command.sh for simplicity and pass it as args to the real
# entrypoint.
if [ -d /.scuba ]; then
    $ENTRYPOINT $(tail -n 1 /.scuba/command.sh)
else
    $ENTRYPOINT $@
fi
