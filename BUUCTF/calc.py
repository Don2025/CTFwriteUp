from pwn import *

def cal(x, y, opertor):
    if opertor == '+':
        return x+y
    elif opertor == '-':
        return x-y
    elif opertor == 'x':
        return x*y
    elif opertor == '/':
        return x/y
    else:
        return 0

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 25690)
elf = ELF('./pwn')
for i in range(100):
    io.recvuntil(b"What's the answer? ")
    n1 = int(io.recvuntil(b' '))
    oper = io.recvuntil(b' ')[:-1].decode()
    n2 = int(io.recvuntil(b' =')[:-2])
    n = cal(n1, n2, oper)
    io.sendline(str(n).encode())
    log.success('%d %c %d = %d' % (n1, oper, n2, n))

io.interactive()