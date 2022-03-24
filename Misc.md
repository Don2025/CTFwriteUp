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

