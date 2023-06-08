from pwn import *

shell = ssh(user='col', host='pwnable.kr', port=2222, password='guest')
hashcode = 0x21DD09EC
a = hashcode//5     # 0x6c5cec8
b = a + hashcode%5  # 0x6c5cecc
payload = p32(a)*4 + p32(b)
# payload = p32(0x6c5cec8)*4 + p32(0x6c5cecc)
io = shell.process(executable='./col', argv=['col', payload])
flag = io.recv()
log.success(flag)  # daddy! I just managed to create a hash collision :)
io.close()
shell.close()