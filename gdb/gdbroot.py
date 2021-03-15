#!/usr/bin/python3
'''
Server for tracing patched sudo. run it with sudo or as root.
Requires 'cmds' file as gdb comamnds in current directory.

Running command:
python gdbroot.py
'''
import os
import time

FIFO_PATH = "/tmp/gdbsudo"

try:
	os.unlink(FIFO_PATH)
except:
	pass

os.umask(0)
os.mkfifo(FIFO_PATH, 0o666)

while True:
	fifo = open(FIFO_PATH, "r")
	pid = int(fifo.read())
	fifo.close()
	cmd = 'gdb -q -p %d < cmds > log 2>&1' % pid
	print('\n=== got: %d. sleep 0.5s' % pid)
	#time.sleep(0.5)
	print(cmd)
	os.system(cmd)
	print('done')
