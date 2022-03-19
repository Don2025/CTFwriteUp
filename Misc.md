# Misc

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

