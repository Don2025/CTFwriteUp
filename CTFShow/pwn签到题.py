from pwn import *

io = remote('pwn.challenge.ctf.show', 28132)
io.interactive()