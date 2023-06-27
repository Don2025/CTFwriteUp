from pwn import *

def getRealEPack(ID,PW):
    io = remote('localhost',9006)
    io.recvuntil(b'ID\n')
    io.sendline(ID.encode())
    io.recvuntil(b'PW\n')
    io.sendline(PW.encode())
    s = io.recvline().decode()
    e_pack = s[s.find('(')+1:-2]
    io.close()
    return e_pack


def getCookie(guess):
    for i in range(2,100):
        pack = '-'*(15-i%16)+'--'+guess
        for j in '1234567890abcdefghijklmnopqrstuvwxyz-_!':
            e_pack0 = getRealEPack(pack+j,'')
            e_pack1 = getRealEPack('-'*(15-i%16),'')
            if e_pack0[:len(pack+j)*2] == e_pack1[:len(pack+j)*2]:
                guess += j
                print(guess)
                break
            if j == '!':
                return guess


def getflag(cookie):
    io = remote('localhost',9006)
    id = 'admin'
    io.sendlineafter(b'Input your ID\n', id)
    pw = hashlib.sha256(id+cookie).hexdigest()
    io.sendlineafter(b'Input your PW\n', pw)
    log.success('ID: {}\nPW: {}'.format(id,term.text.bold_italic_yellow(pw)))
    io.recvuntil(b'hi admin, here is your flag\n')
    flag = io.recvline().decode().strip()
    io.close()
    return flag


context.log_level = 'error'
cookie = getCookie('')  # 'you_will_never_guess_this_sugar_honey_salt_cookie'
context.log_level = 'info'
log.success('Cookie: {}'.format(cookie))
flag = getflag(cookie)
log.success('Flag: {}'.format(term.text.bold_italic_yellow(flag)))