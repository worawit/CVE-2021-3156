#!/usr/bin/python3
'''
Client for tracing patched sudo. Don't forget to start server first before running this.

Running command:
python gdbexp.py exploit.py
'''
import subprocess
import sys
import time


if len(sys.argv) < 2:
	print('Usage: %s <exploit.py> [args...]' % sys.argv[0])
	exit(1)

cmd = 'python'
if sys.version_info[0] == 3:
	cmd += '3'

FIFO_PATH = "/tmp/gdbsudo"

proc = subprocess.Popen([cmd] + sys.argv[1:], stdin=subprocess.PIPE, bufsize=0)
#time.sleep(0.5)

# send to gdber to start debugging
fifo = open(FIFO_PATH, "w")
fifo.write(str(proc.pid))
fifo.close()
time.sleep(0.5)

# trigger enter, resume sudo
proc.stdin.write(b'\n')
proc.stdin.close() # close stdin to exit incase we get shell

ret = proc.wait()
print('exit code: %d' % ret)
