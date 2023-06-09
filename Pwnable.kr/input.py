from pwn import *
import os

args = ['A']*100
args[ord('A')] = '\x00'
args[ord('B')] = '\x20\x0a\x0d'
# Stage 2
r1, w1 = os.pipe()
os.write(w1, b'\x00\x0a\x00\xff')
r2, w2 = os.pipe()
os.write(w2, b'\x00\x0a\x02\xff')
# Stage 3
env = {'\xde\xad\xbe\xef': '\xca\xfe\xba\xbe'}
# Stage 4
with open('\x0a', 'w') as f:
    f.write('\x00\x00\x00\x00')
# Stage 5
port = 6666
args[ord('C')] = str(port)
io = process(executable='/home/input2/input', argv=args, stdin=r1, stderr=r2, env=env)
net = remote('localhost', port)
net.sendline('\xde\xad\xbe\xef')
io.interactive()