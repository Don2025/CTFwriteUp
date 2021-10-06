from pwn import *

io = remote('111.200.241.244', 59901)
io.interactive()