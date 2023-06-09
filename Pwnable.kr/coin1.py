from pwn import *
import re

io = remote('localhost', 9007)
log.info(io.recv())
for _ in range(100):
    msg = io.recv().decode()
    log.info(msg)
    match = re.findall(r'N=(\d+) C=(\d+)', msg)[0]
    if match:
        N, C = int(match[0]), int(match[1])
    begin, end = 0, N-1
    while begin <= end and C > 0:
        mid = (begin + end) // 2
        guess = ' '.join(str(i) for i in range(begin, mid+1))
        io.sendline(guess.encode('utf-8'))
        weight = int(io.recvline()[:-1])
        if weight % 10 == 0:
            begin = mid + 1
        else:
            end = mid - 1
        C -= 1
    for _ in range(C):
        io.sendline(b'0')
        io.recv()
    io.sendline(str(begin).encode('utf-8'))
    log.info(io.recv())


log.success(io.recvline())  # Congrats! get your flag
flag = io.recvline()  # b1NaRy_S34rch1nG_1s_3asy_p3asy
log.success(flag)
io.close()