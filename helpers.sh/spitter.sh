#!/bin/sh

# Clipboard is dangerous because any app can access to the contents of it.
# This script saves the secret to a background process' memory.
# On request, this background process writes this secret to current focused window and exits.
# No background process can access to the secret as long as they are not a focused window.
# If nothing is spitted, the background process kills itself after 20 seconds.

# Recommended usage: PID_FILE's existence indicates the existence of a process ready to spit. Check for this file's existence and show an indicator in your taskbar. Make this button clickable and when gets clicked, spit the secret to the current focused window. You can also assign a keyboard binding for this.

set +x # disable command tracing/debugging
ulimit -c 0 # disable core dumping
umask 077 # make generated files only read/writeable by the owner

# The file containing the PID of the secret spitter background process
PID_FILE="/tmp/secret-spitter.pid"

case "$1" in
	load)
		# Kill the previous instance if running
		if [ -f "$PID_FILE" ]; then
			kill -s TERM "$(cat "$PID_FILE")" 2>/dev/null
			rm -f "$PID_FILE"
		fi

		SECRET_INPUT=$(cat) # get the secret input from stdin

		# Launch a background process
        (
			# Assign secret to a local variable inside the running subshell. It wont appear on /proc/pid/environ
			SECRET="$SECRET_INPUT"
			unset SECRET_INPUT # unset the SECRET_INPUT  local variable in the sub shell

			# Set trap: stream variable directly to wtype on USR1 signal, remove the PID file and exit
			trap '
				printf "%s" "$SECRET" | wtype -
				unset SECRET
				rm -f "$PID_FILE"
				exit 0
			' USR1

			# Set trap: remove the pid file and exit on TERM INT or EXIT
			trap '
				unset SECRET
				rm -f "$PID_FILE"
				exit 0
			' TERM INT EXIT

			# sleep for 20 seconds and exit
			sleep 20 & # wait in the background
			wait $! # wait for sleep command to finish without blocking the shell
        ) &

        VAULT_PID=$! # get the pid of the sub shell
        echo "$VAULT_PID" > "$PID_FILE" # write the pid to the pid file

        # Wipe local variable in caller shell
        unset SECRET_INPUT
        echo "secret stored in PID $VAULT_PID for 20 seconds"
        ;;

    spit)
        if [ -f "$PID_FILE" ]; then
            VAULT_PID=$(cat "$PID_FILE")
            # Send trigger signal to auto-type and purge memory
            kill -s USR1 "$VAULT_PID" 2>/dev/null
        fi
        ;;

    *)
        echo "Usage: $0 {load|spit}"
        ;;
esac
