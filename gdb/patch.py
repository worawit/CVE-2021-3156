#!/usr/bin/python3
'''
Quick and dirty patch for sudo on Linux x64 to pause for character in start of main.
It is used for debugging sudo that run from user environment.

Does not work on very old binaries (from Ubuntu 14.04, CentOS 6)
'''
import sys
import subprocess

orig_file = sys.argv[1]
out_file = sys.argv[2]

patch_data = (
	b'\x31\xc0'  # xor eax, eax
	b'\x31\xff'  # xor edi, edi
	b'\x48\x89\xe6'  # mov rsi, rsp
	b'\xba\x01\x00\x00\x00'  # mov edx, 1
	b'\x0f\x05'  # syscall
)

patch_offset = None
patch_len = None
with subprocess.Popen(['objdump', '-d', '-M', 'intel', orig_file], stdout=subprocess.PIPE, bufsize=1, universal_newlines=True) as proc:
	found_text_section = False
	found_call_sudo_debug = False
	for line in proc.stdout:
		if not found_text_section:
			if line.startswith('Disassembly of section .text:'):
				found_text_section = True
			continue
		
		if not found_call_sudo_debug:
			# just estimate value
			asm = line.strip()[20:]
			if 'call ' in asm and ' <sudo_debug_enter_v1' in asm:
				found_call_sudo_debug = True
			continue
		
		if patch_offset is None:
			line = line.lstrip()
			patch_offset = int(line[:line.index(':')], 16)
			assert patch_offset < 0x10000
			continue
		
		asm = line[20:]
		if 'call ' in asm and ' <fcntl' in asm:
			line = line.lstrip()
			addr = int(line[:line.index(':')], 16)
			patch_len = addr + 5 - patch_offset  # 5 is call instruction length
			break

print('patch offset: 0x{:x}'.format(patch_offset))
print('patch len: 0x{:x}'.format(patch_len))
assert patch_len >= len(patch_data)

patch_data = patch_data.ljust(patch_len, b'\x90')
with open(orig_file, 'rb') as f:
	data = f.read()

with open(out_file, 'wb') as f:
	f.write(data[:patch_offset])
	f.write(patch_data)
	f.write(data[patch_offset+patch_len:])
