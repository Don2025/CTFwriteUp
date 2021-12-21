from pwn import *

shell = ssh(user='col', host='pwnable.kr', port=2222, password='guest')
payload = p32(0x6c5cec8)*4 + p32(0x6c5cecc)
io = shell.process(executable='./col', argv=['col', payload])
flag = io.recv().decode('utf-8')
log.success("Flag => %s", flag)
io.close()
shell.close()