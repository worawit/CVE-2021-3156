#!/usr/bin/python3
'''
For parsing gdb trace log
'''
import re
import sys

break_pattern = re.compile(r'^\w+\s+(\d+),(.*in)?\s+(\w+)\s+\((.*)\) .+$')

record = None
records = []

def new_catch_record(line):
	# now, catch only 1 syscall. get filename
	#pos = line.index('"') + 1
	#epos = line.index('"', pos)
	#fname = line[pos:epos]
	fname = None
	return { 'type': 'open', 'file': fname, 'bt': [] }

def parse_args(txt):
	args = []
	for arg_txt in txt.split(', '):
		if arg_txt[-1] == '"':
			# assume text
			args.append(arg_txt[arg_txt.index('"')+1:-1])
			continue
		
		pos = arg_txt.index('=')
		name = arg_txt[:pos]
		pos += 1
		# argument name might be name=name@entry=
		if name == arg_txt[pos:pos+len(name)]:
			pos += len("@entry=") + len(name)
		args.append(arg_txt[pos:])
	return args

def new_breakpoint_record(line):
	# malloc, free, realloc, calloc
	m = break_pattern.match(line)
	bid, _, fn_name, fn_args = m.groups()
	if bid == '2' and '__libc_malloc' in fn_name: # malloc
		args = parse_args(fn_args)
		return { 'type': 'malloc', 'size': int(args[0]), 'result': None, 'bt': [] }
	elif bid == '4' and '__libc_free' in fn_name: # free
		args = parse_args(fn_args)
		return { 'type': 'free', 'mem': int(args[0], 16), 'bt': [] }
	elif bid == '5' and '__libc_realloc' in fn_name: # realloc
		#if 'realloc_hook_ini' not in line:
		args = parse_args(fn_args)
		return { 'type': 'realloc', 'mem': int(args[0], 16), 'size': int(args[1]), 'result': None, 'bt': [] }
	elif bid == '7' and fn_name == 'nss_load_library':  # nss_load_library
		args = parse_args(fn_args)
		return { 'type': 'nss_load_library', 'addr': int(args[0], 16) }
	elif bid == '8' and fn_name == '__libc_calloc': # calloc
		args = parse_args(fn_args)
		return { 'type': 'calloc', 'n': int(args[0]), 'esize': int(args[1]), 'result': None, 'bt': [] }
			
	return None
	
def update_record_bt(record, line):
	addr = None
	if line[4:6] == '0x':
		addr = int(line[4:22], 16)
		pos = 26
	else:
		pos = 4
	
	epos = line.index(' ', pos)
	fn_name = line[pos:epos]
	pos = epos+1
	assert line[pos] == '('
	pos += 1
	epos = line.find(') at ')
	if epos == -1:
		args = None
		src = line[4:22]
	else:
		args = line[pos:epos]
		src = line[epos + 5:].rstrip()
	record['bt'].append((addr, fn_name, args, src))

def update_record_result(record, line):
	#assert record['result'] is None
	pos = line.index('0x')
	epos = line.find('\t', pos)
	if epos == -1:
		epos = line.index(' ', pos)
	record['result'] = int(line[pos:epos], 16)

# don't go too depth. make it easy to read
# __GI_setlocale
curr_cstack = []
def print_call_stack(bt):
	global curr_cstack
	updated = False
	pos = 0
	for i, info in enumerate(bt):
		addr, fn_name, args, src = info
		# 'nss_load_library', 
		if fn_name in ('__GI_setlocale', 'sudo_conf_read_v1', '__GI___nss_database_lookup', 'nss_parse_service_list', 'nss_new_service', 'get_user_info', 'parse_args', 'sudo_load_plugin', 'format_plugin_settings', 'sudoers_policy_open', 'sudoers_policy_main', 'set_cmnd', 'register_hook'):
			pos = i
			break
	cstack = list(reversed(bt[i:]))
	
	if len(curr_cstack) == len(cstack):
		for old, new in zip(curr_cstack, cstack):
			if old[1] != new[1] or old[3] != new[3]:
				updated = True
				break
	else:
		updated = True
	
	if updated:
		curr_cstack = cstack
		print('')
		for info in cstack:
			addr, fn_name, args, src = info
			if fn_name == '__GI___nss_database_lookup':
				args = parse_args(args)
				print(f'{fn_name}(db={args[0]}, default="{args[2]}")')
			elif fn_name == 'nss_parse_service_list':
				pos = args.index('"') + 1
				pos = args.index('"', pos)
				pos = args.index('"', pos+10) + 1
				epos = args.index('"', pos)
				line = args[pos:epos].strip()
				print(f'{fn_name}("{line}")')
			else:
				print(f'{fn_name} at {src}')
	
def analyze_record(record):
	if record is None:
		return
	
	if record['type'] == 'open':
		return
	if record['type'] == 'nss_load_library':
		print(f"\nnss_load_library(0x{record['addr']:x})\n")
		return
	
	
	print_call_stack(record['bt'])
	if record['type'] == 'malloc':
		chunk_size = (record['size'] + 8 + 15) & 0xfffffff0
		if chunk_size < 0x20:
			chunk_size = 0x20 # min size	
		if record['result']:		
			print(f"- malloc(0x{record['size']:x}) => 0x{record['result']:08x}  => chunk size: 0x{chunk_size:x}")
		else:
			print(f"- malloc(0x{record['size']:x}) => chunk size: 0x{chunk_size:x}")
	elif record['type'] == 'free':
		print(f"- free(0x{record['mem']:08x})")
	elif record['type'] == 'realloc':
		if record['result']:
			print(f"- realloc(0x{record['mem']:08x}, {record['size']}) => 0x{record['result']:08x}")
		else:
			print(f"- realloc(0x{record['mem']:08x}, {record['size']})")
	elif record['type'] == 'calloc':
		chunk_size = ((record['esize']*record['n']) + 8 + 15) & 0xfffffff0
		if chunk_size < 0x20:
			chunk_size = 0x20 # min size			
		print(f"- calloc({record['n']}, {record['esize']}) => 0x{record['result']:08x}  => chunk size: 0x{chunk_size:x}")
	

start = False
with open(sys.argv[1], 'r') as f:
	for line in f:
		if not start:
			line = line.strip()
			if ' Continuing.' in line:
				start = True
			continue
		
		if line.startswith('Catchpoint '):
			analyze_record(record)
			record = new_catch_record(line)
			records.append(record)
		elif line.startswith('Breakpoint '):
			tmp_record = new_breakpoint_record(line)
			if tmp_record is not None:
				analyze_record(record)
				record = tmp_record
				records.append(record)
		elif line.startswith('#'):
			if record is not None:
				update_record_bt(record, line)
		elif line.startswith('r'):
			if record is not None:
				update_record_result(record, line)
	
	analyze_record(record)

