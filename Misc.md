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

### [你竟然赶我走](https://buuoj.cn/challenges#%E4%BD%A0%E7%AB%9F%E7%84%B6%E8%B5%B6%E6%88%91%E8%B5%B0)

这题附件是一个`.jpg`图片，使用`WinHex`打开文件后，在末尾可以看到相应的`ASCII`码信息`flag IS flag{stego_is_s0_bor1ing}`，提交`flag{stego_is_s0_bor1ing}`即可。也可以用`stegSolve`打开，然后`Analyse`→`File Format`在`Ascii`中发现`flag`。

------

### [N种方法解决](https://buuoj.cn/challenges#N%E7%A7%8D%E6%96%B9%E6%B3%95%E8%A7%A3%E5%86%B3)

这题附件是`KEY.exe`，使用`WinHex`打开文件后，发现`ASCII`码信息如下：

```
data:image/jpg;base64,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
```

直接将以上信息复制到`Google Chrome`的网址输入栏中，按下回车键后可以看到一张二维码图片，使用`QR Research`扫描后可以得到`KEY{dca57f966e4e4e31fd5b15417da63269}`，提交`flag{dca57f966e4e4e31fd5b15417da63269}`即可。

------

### [大白](https://buuoj.cn/challenges#%E5%A4%A7%E7%99%BD)

这题附件是`dabai.png`，用`tweakpng`打开图片会弹出提示框`Incorrect crc for IHDR chunk (is 6d7c7135, should be 8e14dfcf)`，双击`IHDR`的`CRC`，把图片的`Height`设置为和`Width`一样的`679`后保存，重新打开图片可以看到`flag{He1l0_d4_ba1}`。

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

