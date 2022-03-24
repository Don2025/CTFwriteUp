# Misc

## BUUCTF

### [签到](https://buuoj.cn/challenges#%E7%AD%BE%E5%88%B0)

提交`flag{buu_ctf}`即可。

------

### [金三胖](https://buuoj.cn/challenges#%E9%87%91%E4%B8%89%E8%83%96)

这题的附件是`.gif`文件，查看`gif`的时候发现有一帧出现了`flag`，编写`Python`代码将`gif`动态图按帧分解为多张静态图片。

```python
from PIL import Image, ImageSequence

src = 'aaa.gif'
suffix='png'
with Image.open(src) as img:
    i = 0
    for frame in ImageSequence.Iterator(img):
        i += 1
        frame.save(f"{i}.{suffix}")
```

程序运行结束后，可以在`21.png`看到`flag{`，`51.png`看到`he11o`，`79.png`看到`hongke}`，提交`flag{he11ohongke}`即可。

------

### [二维码](https://buuoj.cn/challenges#%E4%BA%8C%E7%BB%B4%E7%A0%81)

这题的附件是一个二维码，扫描后显示`secret is here`，并没有什么信息。用`WinHex`打开发现`4number.txt`，盲猜文件里含有`.txt`文件，使用命令行`foremost -i QR_code.png`或者`binwalk -e QR_code.png`可以分离出图片和压缩包，压缩包被加密啦。

使用`fcrackzip`对压缩包进行爆破，根据`4number.txt`这一提示可知密码是4位数字。`fcrackzip`的一些参数如下：

> -b 表示使用暴力破解的方式
>
> -c 'aA1'表示使用大小写字母和数字混合破解的方式
>
> -l 1-16 表示需要破解的密码长度为1~10位
>
> -u 表示只显示破解出来的密码，尝试错误的密码不被显示

我们采用4位数字的暴力破解的方式可以得出压缩包密码是`7639`。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/misc/buuctf]
└─$ fcrackzip -b -c '1' -l 4 -u 1D7.zip

PASSWORD FOUND!!!!: pw == 7639
```

解压缩后打开新的`4number.txt`文件得到`CTF{vjpw_wnoei}`，提交`flag{vjpw_wnoei}`即可。

------

## PwnTheBox

### [迟来的签到题](https://ce.pwnthebox.com/challenges?tag=29&id=962)

题目描述给出的信息如下：

> easy xor???
>
> AAoHAR1XICciX1IlXiBUVFFUIyRRJFRQVyUnVVMnUFcgIiNXXhs=

编写`Python`代码遍历`[0, 256)`进行异或操作，得到`flag{1FAD94C8F2272EB7B261CA35A61FDE18}`。

```python
from base64 import *

s = b64decode('AAoHAR1XICciX1IlXiBUVFFUIyRRJFRQVyUnVVMnUFcgIiNXXhs=')
for i in range(0, 256):
    ans = ''
    for x in s:
        ans += chr(x^i)
    if "flag" in ans:
        print(ans)
```

------

### [对象](https://ce.pwnthebox.com/challenges?type=1&id=497)

打开数据流量包，发现里面有`TCP`和`HTTP`两种协议，直接搜索`flag`没有发现任何信息。挨个观察数据流传输信息，发现大部分数据流都是在传输图片和`gif`，第`188`个数据流是`http`协议数据流，传输的是`text/html`，进行流追踪可以看到 `Hey this is a flag FLAG-GehFMsqCeNvof5szVpB2Dmjx`，提交`FLAG-GehFMsqCeNvof5szVpB2Dmjx`即可。

------

