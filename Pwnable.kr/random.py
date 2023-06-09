from pwn import *

shell = ssh(user='random', host='pwnable.kr', port=2222, password='guest')
io = shell.process('./random')
key = 0x6b8b4567 ^ 0xdeadbeef
payload = str(key).encode()  # 3039230856
io.sendline(payload)
msg = io.recvline()  # Good!
flag = io.recv()  
log.success(flag)  # Mommy, I thought libc random is unpredictable...
io.close()
shell.close()